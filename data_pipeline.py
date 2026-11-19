"""
data_pipeline.py
================
Layer 1 of the full pipeline.

Builds per-slice training CSVs (data/slice_<id>.csv) for federated learning.

Key properties (fixes over the original version):
  * Attack AND benign samples go through the SAME extractor (features.py), so
    the model cannot learn the label from a scaling / generation artefact.
  * Attack payloads are de-duplicated before sampling. The source capture
    contains hundreds of byte-identical copies, which would otherwise leak
    between the train and test splits.
  * Benign traffic is a set of realistic 5G SBI messages (NRF/UDM/AMF/SMF,
    HTTP/1.1, HTTP/2 control frames and normal NF -> MongoDB queries) rather
    than random numbers.

Known limitation: malicious_data.csv is labelled per capture, so it also
contains normal-looking packets (e.g. "100 Continue", ordinary subscriber
lookups). Those rows are label noise; window averaging in the detector
absorbs some of it, but a per-packet labelled capture is the real fix.
  * Each slice gets a different benign traffic mix, so the federation is
    non-IID, which is the setting where FL actually matters.

Optional real benign data: set CFG["benign_csv"] to a CSV with the same
format as malicious_data.csv (a "raw" column of hex payloads), e.g. a capture
of normal Open5GS/free5GC + UERANSIM traffic.
"""

import os
import random
import struct
import uuid

import numpy as np
import pandas as pd

from features import FEATURE_NAMES, N_SLICES, decode_hex_payload, extract_features

CFG = {
    "malicious_csv":     "malicious_data.csv",
    "benign_csv":        None,          # CSV with a hex "raw" column of benign payloads
    "output_dir":        "data",
    "n_slices":          N_SLICES,
    "samples_per_slice": 500,           # per class per slice
    "random_seed":       42,
}

# Relative weight of each benign message family per slice (non-IID split).
SLICE_BENIGN_MIX = {
    0: {"pdu_session": 4, "nrf_disc": 2, "udm_sdm": 1, "amf_comm": 1, "nf_register": 1, "h2_control": 2, "mongo": 3},  # eMBB
    1: {"pdu_session": 1, "nrf_disc": 3, "udm_sdm": 2, "amf_comm": 3, "nf_register": 1, "h2_control": 2, "mongo": 3},  # URLLC
    2: {"pdu_session": 1, "nrf_disc": 1, "udm_sdm": 1, "amf_comm": 1, "nf_register": 4, "h2_control": 2, "mongo": 3},  # mMTC
}

NF_TYPES = ["AMF", "SMF", "UDM", "AUSF", "PCF", "NSSF", "UDR", "BSF"]


# ─────────────────────────────────────────────────────────────
# ATTACK DATA
# ─────────────────────────────────────────────────────────────

def load_payload_csv(path: str) -> list:
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    payloads = [decode_hex_payload(r) for r in df["raw"]]
    return [p for p in payloads if p]


def load_attack_payloads(path: str) -> list:
    print(f"[DataPipeline] Loading attack data from {path}")
    payloads = load_payload_csv(path)
    unique = list(dict.fromkeys(payloads))
    print(f"  Raw rows: {len(payloads)}  ->  unique payloads: {len(unique)}")
    return unique


# ─────────────────────────────────────────────────────────────
# BENIGN SBI TRAFFIC GENERATOR
# ─────────────────────────────────────────────────────────────

def _http_request(method, path, body=""):
    hdr = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.{random.randint(2, 30)}:7777\r\n"
           f"User-Agent: {random.choice(NF_TYPES)}\r\nAccept: application/json\r\n")
    if body:
        hdr += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    return (hdr + "\r\n" + body).encode()


def _http_response(status, body=""):
    reason = {200: "OK", 201: "Created", 204: "No Content", 404: "Not Found"}[status]
    hdr = f"HTTP/1.1 {status} {reason}\r\nDate: Thu, 09 Jun 2022 21:14:54 GMT\r\n"
    if body:
        hdr += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    return (hdr + "\r\n" + body).encode()


def _imsi():
    return f"imsi-20893{random.randint(0, 99999999):010d}"


def _nf_profile(nf_type):
    return ('{"nfInstanceId":"%s","nfType":"%s","nfStatus":"REGISTERED",'
            '"ipv4Addresses":["127.0.0.%d"],"sNssais":[{"sst":%d}]}'
            % (uuid.uuid4(), nf_type, random.randint(2, 30), random.randint(1, 3)))


def _bson(doc: dict) -> bytes:
    """Minimal BSON encoder (str, int, float, bool, dict, list) for synthetic MongoDB traffic."""
    out = b""
    for k, v in doc.items():
        key = k.encode() + b"\x00"
        if isinstance(v, bool):
            out += b"\x08" + key + (b"\x01" if v else b"\x00")
        elif isinstance(v, int):
            out += b"\x10" + key + struct.pack("<i", v)
        elif isinstance(v, float):
            out += b"\x01" + key + struct.pack("<d", v)
        elif isinstance(v, str):
            b = v.encode() + b"\x00"
            out += b"\x02" + key + struct.pack("<i", len(b)) + b
        elif isinstance(v, dict):
            out += b"\x03" + key + _bson(v)
        elif isinstance(v, list):
            out += b"\x04" + key + _bson({str(i): x for i, x in enumerate(v)})
    return struct.pack("<i", len(out) + 5) + out + b"\x00"


def _op_msg(doc: dict, response_to: int = 0) -> bytes:
    """MongoDB OP_MSG (opcode 2013) as sent by the free5GC NFs to their database."""
    body = struct.pack("<I", 0) + b"\x00" + _bson(doc)
    header = struct.pack("<iiii", 16 + len(body), random.randint(1, 2**31 - 1), response_to, 2013)
    return header + body


def _gen_mongo() -> bytes:
    imsi = _imsi()
    if random.random() < 0.5:
        coll = random.choice(["NfProfile", "subscriptionData.provisionedData.amData",
                              "subscriptionData.provisionedData.smData", "policyData.ues.amData"])
        flt = ({"nfType": random.choice(NF_TYPES)} if coll == "NfProfile"
               else {"ueId": imsi, "servingPlmnId": "20893"})
        return _op_msg({"find": coll, "filter": flt, "limit": 1, "singleBatch": True,
                        "lsid": {"id": uuid.uuid4().hex}, "$db": "free5gc"})
    batch = [{"ueId": imsi, "servingPlmnId": "20893", "gpsis": ["msisdn-0900000000"],
              "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"},
              "nssai": {"defaultSingleNssais": [{"sst": 1.0, "sd": "010203"}]}}]
    return _op_msg({"cursor": {"firstBatch": batch, "id": 0, "ns": "free5gc.subscriptionData"},
                    "ok": 1.0}, response_to=random.randint(1, 2**31 - 1))


def _gen(family: str) -> bytes:
    if family == "mongo":
        return _gen_mongo()
    if family == "nrf_disc":
        if random.random() < 0.5:
            tgt, req = random.sample(NF_TYPES, 2)
            return _http_request("GET", f"/nnrf-disc/v1/nf-instances?target-nf-type={tgt}"
                                        f"&requester-nf-type={req}")
        body = '{"validityPeriod":3600,"nfInstances":[%s]}' % _nf_profile(random.choice(NF_TYPES))
        return _http_response(200, body)
    if family == "udm_sdm":
        if random.random() < 0.5:
            part = random.choice(["am-data", "smf-select-data", "nssai", "sm-data"])
            return _http_request("GET", f"/nudm-sdm/v2/{_imsi()}/{part}")
        return _http_response(200, '{"gpsis":["msisdn-0900000000"],"nssai":{"defaultSingleNssais":[{"sst":1}]}}')
    if family == "amf_comm":
        if random.random() < 0.5:
            body = '{"n1MessageContainer":{"n1MessageClass":"5GMM"},"pduSessionId":%d}' % random.randint(1, 15)
            return _http_request("POST", f"/namf-comm/v1/ue-contexts/{_imsi()}/n1-n2-messages", body)
        return _http_response(200, '{"cause":"N1_N2_TRANSFER_INITIATED"}')
    if family == "pdu_session":
        if random.random() < 0.5:
            body = '{"supi":"%s","pduSessionId":%d,"dnn":"internet","sNssai":{"sst":1}}' % (_imsi(), random.randint(1, 15))
            return _http_request("POST", "/nsmf-pdusession/v1/sm-contexts", body)
        return _http_response(random.choice([201, 204]), "" if random.random() < 0.5 else '{"upCnxState":"ACTIVATED"}')
    if family == "nf_register":
        r = random.random()
        if r < 0.4:
            body = _nf_profile(random.choice(NF_TYPES))
            return _http_request("PUT", f"/nnrf-nfm/v1/nf-instances/{uuid.uuid4()}", body)
        if r < 0.7:
            return _http_request("PATCH", f"/nnrf-nfm/v1/nf-instances/{uuid.uuid4()}",
                                 '[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]')
        return _http_response(random.choice([200, 201, 204, 404]))
    if family == "h2_control":
        # HTTP/2 connection preface, SETTINGS, SETTINGS-ACK, WINDOW_UPDATE, PING
        frames = [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000012040000000000000300000064000400100000000600002000"),
            bytes.fromhex("000000040100000000"),
            bytes.fromhex("0000040800000000000000ffff"),
            bytes.fromhex("0000080600000000000102030405060708"),
        ]
        return random.choice(frames)
    raise ValueError(family)


def generate_benign_payloads(n: int, slice_id: int) -> list:
    mix = SLICE_BENIGN_MIX[slice_id]
    families = random.choices(list(mix), weights=list(mix.values()), k=n)
    return [_gen(f) for f in families]


# ─────────────────────────────────────────────────────────────
# DATASET BUILD
# ─────────────────────────────────────────────────────────────

def _to_frame(payloads: list, slice_id: int, label: int) -> pd.DataFrame:
    X = np.stack([extract_features(p, slice_id) for p in payloads])
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = label
    return df


def build_slice_datasets(attack_payloads: list, benign_pool: list = None) -> None:
    os.makedirs(CFG["output_dir"], exist_ok=True)
    n = CFG["samples_per_slice"]
    rng = np.random.default_rng(CFG["random_seed"])

    # Give each slice a disjoint share of the unique attack payloads where possible.
    order = rng.permutation(len(attack_payloads))
    shares = np.array_split(order, CFG["n_slices"])

    for slice_id in range(CFG["n_slices"]):
        share = [attack_payloads[i] for i in shares[slice_id]]
        atk_idx = rng.choice(len(share), size=n, replace=len(share) < n)
        atk = [share[i] for i in atk_idx]

        if benign_pool:
            ben = [benign_pool[i] for i in rng.choice(len(benign_pool), size=n, replace=len(benign_pool) < n)]
        else:
            ben = generate_benign_payloads(n, slice_id)

        combined = pd.concat([_to_frame(atk, slice_id, 1), _to_frame(ben, slice_id, 0)],
                             ignore_index=True)
        combined = combined.sample(frac=1, random_state=CFG["random_seed"]).reset_index(drop=True)

        out_path = os.path.join(CFG["output_dir"], f"slice_{slice_id}.csv")
        combined.to_csv(out_path, index=False)
        print(f"  Slice {slice_id}: {len(combined)} rows ({n} attack from {len(share)} unique, "
              f"{n} benign) -> {out_path}")


def run():
    print("=" * 60)
    print("  DATA PIPELINE — 5G Slice Security")
    print("=" * 60)
    random.seed(CFG["random_seed"])

    attack_payloads = load_attack_payloads(CFG["malicious_csv"])

    benign_pool = None
    if CFG["benign_csv"] and os.path.exists(CFG["benign_csv"]):
        print(f"[DataPipeline] Loading benign payloads from {CFG['benign_csv']}")
        benign_pool = list(dict.fromkeys(load_payload_csv(CFG["benign_csv"])))
    else:
        print("[DataPipeline] No benign capture configured — generating realistic benign SBI traffic")
        print("  -> For real results, capture normal Open5GS + UERANSIM traffic and set CFG['benign_csv']")

    build_slice_datasets(attack_payloads, benign_pool)
    print(f"\n[DataPipeline] Done — slice CSVs saved to {CFG['output_dir']}/")


if __name__ == "__main__":
    run()
