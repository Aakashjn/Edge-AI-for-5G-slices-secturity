"""
attack_simulation.py
====================
Injects traffic into the detection pipeline so the demo exercises the real
path:  traffic -> Kafka -> DetectionEngine (model) -> ResponseEngine (SDN) -> audit log.

It does NOT write to the audit log itself — if the model does not flag the
traffic, nothing is isolated.

Two transports:
  kafka (default) — publishes telemetry messages in the same format as
                    packet_sniffer.py to the slice-telemetry topic
  http            — sends real HTTP requests to an SBI endpoint (e.g. an
                    Open5GS NRF at http://127.0.0.10:7777) so the packet
                    sniffer captures them off the wire

Usage:
  python attack_simulation.py --slice 1 --attack nosql
  python attack_simulation.py --slice 0 --attack benign       # should NOT alert
  python attack_simulation.py --slice 1 --attack nosql --transport http --target http://127.0.0.10:7777
"""

import argparse
import json
import os
import random
import time
from datetime import datetime

from features import SLICE_NAMES, extract_features, extract_iocs

ATTACKS = ("nosql", "benign")


def build_payloads(attack: str, slice_id: int, count: int) -> list:
    import data_pipeline
    if attack == "benign":
        return data_pipeline.generate_benign_payloads(count, slice_id)
    attacks = data_pipeline.load_attack_payloads(data_pipeline.CFG["malicious_csv"])
    injections = [p for p in attacks if extract_iocs(p)] or attacks
    return [random.choice(injections) for _ in range(count)]


def send_kafka(payloads, slice_id, broker, topic):
    from kafka import KafkaProducer
    producer = KafkaProducer(bootstrap_servers=broker,
                             value_serializer=lambda v: json.dumps(v).encode("utf-8"))
    src = f"10.{slice_id + 1}0.0.66"
    for p in payloads:
        producer.send(topic, {
            "features": extract_features(p, slice_id).tolist(),
            "slice_id": slice_id, "src_ip": src, "dst_ip": "127.0.0.10",
            "timestamp": datetime.now().isoformat(), "payload_hex": p[:1000].hex(),
        })
        time.sleep(0.01)
    producer.flush()


def send_http(payloads, target):
    import requests
    sent = 0
    for p in payloads:
        text = p.decode("utf-8", "replace")
        if not text.startswith(("GET ", "POST ", "PUT ", "PATCH ")):
            continue                      # only replay HTTP/1.1 requests
        method, path = text.split(" ", 2)[:2]
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else None
        try:
            requests.request(method, target.rstrip("/") + path, data=body, timeout=2)
        except requests.RequestException:
            pass
        sent += 1
    return sent


def main():
    ap = argparse.ArgumentParser(description="Inject attack/benign SBI traffic into SliceShield")
    ap.add_argument("--slice", type=int, default=1, choices=sorted(SLICE_NAMES))
    ap.add_argument("--attack", default="nosql", choices=ATTACKS)
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--transport", choices=["kafka", "http"], default="kafka")
    ap.add_argument("--broker", default=os.getenv("KAFKA_BROKER", "localhost:9093"))
    ap.add_argument("--topic", default=os.getenv("KAFKA_TOPIC", "slice-telemetry"))
    ap.add_argument("--target", default="http://127.0.0.10:7777", help="SBI base URL for --transport http")
    args = ap.parse_args()

    payloads = build_payloads(args.attack, args.slice, args.count)
    print(f"[sim] {args.attack.upper()} x{len(payloads)} -> slice {args.slice} "
          f"({SLICE_NAMES[args.slice]}) via {args.transport}")
    if args.transport == "kafka":
        send_kafka(payloads, args.slice, args.broker, args.topic)
    else:
        n = send_http(payloads, args.target)
        print(f"[sim] sent {n} HTTP requests to {args.target}")
    print("[sim] done — detection/response outcome will appear in logs/response_audit.jsonl")


if __name__ == "__main__":
    main()
