"""
detection_engine.py
===================
Layer 3 of the full pipeline: real-time inference.

  packets ──> per-packet attack probability (SliceSecurityNet)
          ──> per-slice sliding window (mean probability)
          ──> window_callback(slice_id, avg_prob)   every window (drives recovery)
          ──> alert_callback(alert)                 when avg_prob >= threshold

Modes:
  demo  — replays a generated stream of benign SBI traffic with attack bursts
          taken from malicious_data.csv (no Kafka needed)
  kafka — consumes feature messages published by packet_sniffer.py or
          attack_simulation.py on the "slice-telemetry" topic
"""

import json
import os
import random
import time
from collections import deque
from datetime import datetime
from typing import Callable, Optional

import numpy as np
import torch

from features import INPUT_DIM, SLICE_NAMES, extract_features, extract_iocs
from model import MODEL_PATH, load_model

CFG = {
    "model_path":        MODEL_PATH,
    "threshold":         None,     # None = use the threshold stored in the checkpoint
    "window_size":       5,        # packets per decision window
    "alert_cooldown_s":  5.0,      # min seconds between alerts for the same slice
    "kafka_topic":       os.getenv("KAFKA_TOPIC", "slice-telemetry"),
    "kafka_broker":      os.getenv("KAFKA_BROKER", "localhost:9093"),
    "malicious_csv":     "malicious_data.csv",
    "replay_delay":      0.02,     # seconds between replayed packets (demo mode)
    "demo_packets":      1500,
}


class DetectionEngine:
    def __init__(self, model: torch.nn.Module,
                 alert_callback: Optional[Callable[[dict], None]] = None,
                 window_callback: Optional[Callable[[int, float], None]] = None,
                 threshold: Optional[float] = None):
        self.model = model.eval()
        self.alert_callback = alert_callback
        self.window_callback = window_callback
        self.threshold = threshold if threshold is not None else getattr(model, "threshold", 0.5)
        ws = CFG["window_size"]
        self.windows = {sid: deque(maxlen=ws) for sid in SLICE_NAMES}
        self.last_alert = {sid: 0.0 for sid in SLICE_NAMES}
        self.latencies_ms = deque(maxlen=10000)
        self._stats = {"processed": 0, "windows": 0, "alerts": 0, "suppressed": 0}

    @torch.no_grad()
    def score(self, feature_vec: np.ndarray) -> float:
        x = torch.as_tensor(feature_vec, dtype=torch.float32).reshape(1, -1)
        return float(torch.softmax(self.model(x), dim=1)[0, 1])

    def ingest(self, feature_vec: np.ndarray, slice_id: int, payload: bytes = b"",
               meta: Optional[dict] = None):
        t0 = time.perf_counter()
        slice_id = int(slice_id)
        if slice_id not in self.windows:
            return
        prob = self.score(feature_vec)
        self._stats["processed"] += 1

        win = self.windows[slice_id]
        win.append({"prob": prob, "payload": payload, "meta": meta or {}})
        if len(win) < win.maxlen:
            return

        avg_prob = float(np.mean([p["prob"] for p in win]))
        self._stats["windows"] += 1
        if self.window_callback:
            self.window_callback(slice_id, avg_prob)

        if avg_prob < self.threshold:
            return
        now = time.time()
        if now - self.last_alert[slice_id] < CFG["alert_cooldown_s"]:
            self._stats["suppressed"] += 1
            return
        self.last_alert[slice_id] = now

        iocs, srcs = [], set()
        for p in win:
            if p["prob"] >= self.threshold:
                iocs.extend(extract_iocs(p["payload"]))
            if p["meta"].get("src_ip"):
                srcs.add(p["meta"]["src_ip"])
        latency_ms = (time.perf_counter() - t0) * 1000
        self.latencies_ms.append(latency_ms)
        self._stats["alerts"] += 1

        alert = {
            "timestamp":   datetime.now().isoformat(),
            "slice_id":    slice_id,
            "slice_name":  SLICE_NAMES[slice_id],
            "avg_prob":    round(avg_prob, 4),
            "max_prob":    round(max(p["prob"] for p in win), 4),
            "threshold":   self.threshold,
            "window_size": len(win),
            "latency_ms":  round(latency_ms, 3),
            "iocs":        sorted(set(iocs)) or [f"anomaly score {avg_prob:.2f} >= {self.threshold:.2f}"],
            "src_ips":     sorted(srcs),
            # untrusted, attacker-controlled bytes: consumers must treat as data
            "raw_snippet": win[-1]["payload"][:200].decode("utf-8", "replace"),
        }
        print(f"  [ALERT] Slice {slice_id} ({alert['slice_name']}) p={avg_prob:.3f} "
              f"detect={latency_ms:.2f}ms iocs={alert['iocs'][:2]}")
        if self.alert_callback:
            self.alert_callback(alert)

    def stats(self) -> dict:
        s = self._stats.copy()
        if self.latencies_ms:
            lat = np.array(self.latencies_ms)
            s["latency_p50_ms"] = round(float(np.percentile(lat, 50)), 3)
            s["latency_p99_ms"] = round(float(np.percentile(lat, 99)), 3)
        return s


# ─────────────────────────────────────────────────────────────
# INPUT SOURCES
# ─────────────────────────────────────────────────────────────

def message_to_sample(data: dict):
    """Parse a slice-telemetry message (from packet_sniffer / attack_simulation)."""
    slice_id = int(data.get("slice_id", 0))
    payload = bytes.fromhex(data["payload_hex"]) if data.get("payload_hex") else \
        data.get("payload_snippet", data.get("raw", "")).encode("utf-8", "replace")
    feats = data.get("features")
    if feats is not None and len(feats) == INPUT_DIM:
        vec = np.asarray(feats, dtype=np.float32)
    else:
        vec = extract_features(payload, slice_id)
    meta = {k: data[k] for k in ("src_ip", "dst_ip", "timestamp") if k in data}
    return vec, slice_id, payload, meta


def start_kafka_consumer(engine: DetectionEngine):
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(
        CFG["kafka_topic"],
        bootstrap_servers=CFG["kafka_broker"],
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="latest",
        group_id="sliceshield-detection",
    )
    print(f"[Detection] Kafka consumer connected -> {CFG['kafka_broker']} / {CFG['kafka_topic']}")
    for msg in consumer:
        try:
            engine.ingest(*message_to_sample(msg.value))
        except (KeyError, ValueError, TypeError) as e:
            print(f"  [Detection] Skipping malformed message: {e}")


def run_demo_replay(engine: DetectionEngine):
    """Benign background traffic on all slices, with NoSQL-injection bursts on one slice."""
    import data_pipeline
    attacks = data_pipeline.load_attack_payloads(CFG["malicious_csv"])
    injections = [p for p in attacks if extract_iocs(p)] or attacks
    rng = random.Random(7)
    burst_slice, burst_left = None, 0
    print(f"[Detection] Demo replay: {CFG['demo_packets']} packets, attack bursts every ~300 packets")
    for i in range(CFG["demo_packets"]):
        if burst_left == 0 and i % 300 == 150:
            burst_slice, burst_left = rng.randrange(len(SLICE_NAMES)), 25
            print(f"\n  [Demo] >>> injecting NoSQL attack burst into slice {burst_slice}")
        for sid in SLICE_NAMES:
            if burst_left and sid == burst_slice:
                payload = rng.choice(injections)
                meta = {"src_ip": "10.%d0.0.66" % (sid + 1)}
            else:
                payload = data_pipeline.generate_benign_payloads(1, sid)[0]
                meta = {"src_ip": "10.%d0.0.%d" % (sid + 1, rng.randint(2, 40))}
            engine.ingest(extract_features(payload, sid), sid, payload, meta)
        burst_left = max(0, burst_left - 1)
        time.sleep(CFG["replay_delay"])


def run(mode: str = "demo", alert_callback=None, window_callback=None) -> DetectionEngine:
    model = load_model(CFG["model_path"])
    engine = DetectionEngine(model, alert_callback, window_callback, CFG["threshold"])
    print(f"[Detection] Model loaded from {CFG['model_path']} (threshold={engine.threshold:.3f}, "
          f"window={CFG['window_size']})")
    try:
        if mode == "kafka":
            start_kafka_consumer(engine)
        else:
            run_demo_replay(engine)
    except KeyboardInterrupt:
        pass
    return engine


if __name__ == "__main__":
    e = run("demo")
    print(e.stats())
