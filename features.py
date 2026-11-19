"""
features.py
===========
Single source of truth for the 20-dimensional feature vector.

Used by BOTH training (data_pipeline.py) and live capture (packet_sniffer.py),
so the model sees exactly the same features at train and inference time.
"""

import re
from typing import Union

import numpy as np

N_SLICES = 3
SLICE_NAMES = {0: "eMBB", 1: "URLLC", 2: "mMTC"}

FEATURE_NAMES = [
    "http_method",       # 0  GET=1 ... OPTIONS=7, normalised /7
    "nrf_discovery",     # 1  /nnrf-disc/
    "nrf_management",    # 2  /nnrf-nfm/
    "udm_access",        # 3  /nudm-sdm/
    "nosql_keyword",     # 4  MongoDB operators / NfProfile query
    "http_status",       # 5  status / 600
    "content_length",    # 6  Content-Length / 10000
    "payload_length",    # 7  bytes / 5000
    "mongo_query",       # 8  find + NfProfile
    "mongo_error",       # 9  errmsg in body
    "mongo_op",          # 10 MongoDB command keyword
    "is_5xx",            # 11
    "is_4xx",            # 12
    "injection_depth",   # 13 count("$") / 20
    "imsi_access",       # 14 imsi- / supi in payload
    "is_request",        # 15
    "is_response",       # 16
    "text_len",          # 17 printable chars in first 1000 bytes / 1000
    "slice_id",          # 18 slice / N_SLICES
    "is_http2",          # 19 HTTP/2 preface or binary frame
]
INPUT_DIM = len(FEATURE_NAMES)

_METHODS = {"GET": 1, "POST": 2, "PUT": 3, "PATCH": 4,
            "DELETE": 5, "HEAD": 6, "OPTIONS": 7}
_NOSQL_OPS = ("$and", "$or", "$nor", "$gt", "$lt", "$ne", "$regex",
              "$where", "$in", "$exists")
_STATUS_RE = re.compile(r"HTTP/[12](?:\.\d)? (\d{3})")
_CLEN_RE = re.compile(r"content-length:\s*(\d+)", re.IGNORECASE)


def decode_hex_payload(raw: str) -> bytes:
    """Decode the b'<hex>' format used in malicious_data.csv."""
    raw = str(raw).strip()
    if raw.startswith("b'") and raw.endswith("'"):
        raw = raw[2:-1]
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return b""


def _looks_http2(data: bytes) -> bool:
    if data.startswith(b"PRI * HTTP/2.0"):
        return True
    # HTTP/2 frame header: 3-byte length, 1-byte type (0-9), 1-byte flags,
    # 4-byte stream id (top bit reserved). A segment may carry several frames,
    # so the first frame only has to fit inside the payload.
    if len(data) < 9 or data[3] > 0x09 or data[5] & 0x80:
        return False
    return int.from_bytes(data[:3], "big") + 9 <= len(data)


def extract_features(payload: Union[bytes, str], slice_id: int = 0) -> np.ndarray:
    """Turn one SBI packet payload into a float32 vector of length INPUT_DIM."""
    data = payload.encode("utf-8", "replace") if isinstance(payload, str) else payload
    text = data[:1000].decode("utf-8", errors="replace")
    low = text.lower()

    method = next((v for k, v in _METHODS.items() if text.startswith(k + " ")), 0)

    status = 0
    m = _STATUS_RE.search(text)
    if m:
        status = int(m.group(1))

    clen = 0
    m = _CLEN_RE.search(text)
    if m:
        clen = int(m.group(1))

    has_nosql_op = any(op in text for op in _NOSQL_OPS)
    mongo_cmd = any(k in text for k in ("find", "aggregate", "db.runCommand", '{"find"'))
    printable = sum(1 for c in text if c.isprintable())

    vec = [
        method / 7.0,
        float("/nnrf-disc/" in text),
        float("/nnrf-nfm/" in text),
        float("/nudm-sdm/" in text),
        float(has_nosql_op or ("find" in text and "NfProfile" in text)),
        min(status, 599) / 600.0,
        min(clen, 10000) / 10000.0,
        min(len(data), 5000) / 5000.0,
        float("find" in text and "NfProfile" in text),
        float("errmsg" in text),
        float(mongo_cmd),
        float(500 <= status < 600),
        float(400 <= status < 500),
        min(text.count("$"), 20) / 20.0,
        float("imsi-" in low or "supi" in low),
        float(method > 0),
        float(status > 0),
        min(printable, 1000) / 1000.0,
        (slice_id % N_SLICES) / N_SLICES,
        float(_looks_http2(data)),
    ]
    return np.asarray(vec, dtype=np.float32)


def extract_iocs(payload: Union[bytes, str]) -> list:
    """Human-readable indicators of compromise, used to pick a response playbook."""
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
    iocs = []
    ops = [op for op in _NOSQL_OPS if op in text]
    if ops:
        iocs.append(f"nosql operators in SBI request: {', '.join(ops)}")
    if "errmsg" in text:
        iocs.append("nosql backend error leaked in response (errmsg)")
    if "/nnrf-disc/" in text and ("$" in text or "target-nf-type=&" in text or "target-nf-type= " in text):
        iocs.append("malformed NRF discovery query")
    if "/nudm-sdm/" in text and "imsi-" in text.lower():
        iocs.append("subscriber data (SUPI/IMSI) access via UDM")
    if " 500 " in text[:40]:
        iocs.append("NF returned HTTP 500")
    return iocs
