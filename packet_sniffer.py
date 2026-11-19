"""
packet_sniffer.py
=================
Live packet capture daemon — replaces CSV replay for production.
Taps the UPF (User Plane Function) network interface,
extracts features from live 5G SBI traffic in real time,
and publishes feature vectors to Kafka.

Requires:
    pip install scapy kafka-python numpy
    sudo setcap cap_net_raw+eip $(which python3)   # or run as root

Usage:
    # Tap eth0, publish to local Kafka
    python packet_sniffer.py

    # Specific interface + remote Kafka
    python packet_sniffer.py --interface upf0 --broker 192.168.1.10:9092

    # Dry run (print features, don't publish)
    python packet_sniffer.py --dry-run

Architecture:
    [5G UPF interface]
          ↓  scapy AsyncSniffer
    [Feature extractor]
          ↓  JSON feature vector
    [Kafka producer] → topic: "slice-telemetry"
          ↓
    [detection_engine.py consumer]
"""

import os
import sys
import json
import time
import queue
import argparse
import threading
import ipaddress
from datetime import datetime
from typing import Optional

from features import extract_features

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "interface":      os.getenv("INTERFACE", "eth0"),
    "kafka_broker":   os.getenv("KAFKA_BROKER", "localhost:9093"),
    "kafka_topic":    os.getenv("KAFKA_TOPIC", "slice-telemetry"),
    "batch_size":     10,           # publish N packets at once
    "batch_timeout":  0.5,          # max seconds to wait before flushing
    "queue_maxsize":  5000,
    "max_payload":    1000,         # bytes of payload forwarded (hex) for IoCs / RCA
    # 5G SBI port (NRF/UDM/SMF all listen on 7777 by default in Open5GS)
    "sbi_port":       7777,
    # Slice IP ranges — map source IP to slice
    "slice_ranges": {
        0: "10.10.0.0/24",   # eMBB
        1: "10.20.0.0/24",   # URLLC
        2: "10.30.0.0/24",   # mMTC
    },
    "dry_run":        False,
}

# 5G SBI endpoint → attack relevance score
SBI_ENDPOINTS = {
    "/nnrf-disc/":  {"nrf_disc": 1},
    "/nnrf-nfm/":   {"nrf_mgmt": 1},
    "/nudm-sdm/":   {"udm_access": 1},
    "/nsmf-pdusession/": {},
    "/namf-comm/":  {},
}

# ─────────────────────────────────────────────────────────────
# SLICE RESOLVER
# ─────────────────────────────────────────────────────────────

_slice_nets = {
    sid: ipaddress.IPv4Network(cidr)
    for sid, cidr in CFG["slice_ranges"].items()
}

def resolve_slice(src_ip: str) -> int:
    try:
        addr = ipaddress.IPv4Address(src_ip)
        for sid, net in _slice_nets.items():
            if addr in net:
                return sid
    except Exception:
        pass
    return 0   # unknown source -> eMBB (default slice)

# ─────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR
# ─────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Wraps features.extract_features (the SAME code used to build the training
    set) for live scapy packets.

    Note: plaintext only. Production SBI is HTTP/2 over TLS; HTTP/2 frames are
    flagged (is_http2) but HPACK headers are not decoded yet.
    """

    def extract(self, pkt) -> Optional[dict]:
        """Return a telemetry message or None if the packet is not SBI traffic."""
        from scapy.layers.inet import IP, TCP

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None
        tcp = pkt[TCP]
        if CFG["sbi_port"] not in (tcp.dport, tcp.sport):
            return None
        payload = bytes(tcp.payload)
        if not payload:
            return None          # bare SYN/ACK etc.

        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        slice_id = resolve_slice(src_ip)
        return {
            "features":    extract_features(payload, slice_id).tolist(),
            "slice_id":    slice_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "timestamp":   datetime.now().isoformat(),
            "payload_hex": payload[:CFG["max_payload"]].hex(),
        }

# ─────────────────────────────────────────────────────────────
# KAFKA PUBLISHER
# ─────────────────────────────────────────────────────────────

class KafkaPublisher:
    def __init__(self, broker: str, topic: str, dry_run: bool = False):
        self.topic   = topic
        self.dry_run = dry_run
        self.producer = None
        self._stats = {"published": 0, "errors": 0}

        if not dry_run:
            try:
                from kafka import KafkaProducer
                self.producer = KafkaProducer(
                    bootstrap_servers=broker,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    acks="all",
                    retries=3,
                    linger_ms=50,   # small batching delay for throughput
                )
                print(f"[Sniffer] Kafka producer connected → {broker}")
            except ImportError:
                print("[Sniffer] kafka-python not installed — dry run mode")
                self.dry_run = True
            except Exception as e:
                print(f"[Sniffer] Kafka connection failed: {e} — dry run mode")
                self.dry_run = True

    def publish(self, feature_dict: dict):
        if self.dry_run:
            sid = feature_dict.get("slice_id", 0)
            feat = feature_dict.get("features", [])
            print(f"  [DryRun] Slice {sid}  {feature_dict.get('src_ip')} -> {feature_dict.get('dst_ip')}  "
                  f"features=[{', '.join(f'{v:.2f}' for v in feat[:6])}...]")
            self._stats["published"] += 1
            return

        try:
            self.producer.send(self.topic, value=feature_dict)
            self._stats["published"] += 1
        except Exception as e:
            self._stats["errors"] += 1
            print(f"  [Kafka] Publish error: {e}")

    def flush(self):
        if self.producer:
            self.producer.flush()

    def stats(self):
        return self._stats.copy()

# ─────────────────────────────────────────────────────────────
# SNIFFER
# ─────────────────────────────────────────────────────────────

class PacketSniffer:
    def __init__(self, interface: str, publisher: KafkaPublisher):
        self.interface = interface
        self.publisher = publisher
        self.extractor = FeatureExtractor()
        self._queue    = queue.Queue(maxsize=CFG["queue_maxsize"])
        self._stats    = {"captured": 0, "processed": 0, "dropped": 0}
        self._running  = False

    def _packet_callback(self, pkt):
        self._stats["captured"] += 1
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._stats["dropped"] += 1

    def _processor_thread(self):
        """Batch-process packets from the queue and publish to Kafka."""
        batch = []
        last_flush = time.time()

        while self._running:
            try:
                pkt = self._queue.get(timeout=0.1)
                features = self.extractor.extract(pkt)
                if features:
                    batch.append(features)
                    self._stats["processed"] += 1

                now = time.time()
                if len(batch) >= CFG["batch_size"] or \
                   (batch and now - last_flush >= CFG["batch_timeout"]):
                    for feat in batch:
                        self.publisher.publish(feat)
                    self.publisher.flush()
                    batch = []
                    last_flush = now

            except queue.Empty:
                # Flush remaining on timeout
                if batch:
                    for feat in batch:
                        self.publisher.publish(feat)
                    self.publisher.flush()
                    batch = []
                    last_flush = time.time()

    def _stats_thread(self):
        """Print stats every 10 seconds."""
        while self._running:
            time.sleep(10)
            pub = self.publisher.stats()
            print(f"  [Stats] captured={self._stats['captured']}  "
                  f"processed={self._stats['processed']}  "
                  f"dropped={self._stats['dropped']}  "
                  f"published={pub['published']}  "
                  f"errors={pub['errors']}")

    def start(self):
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            print("[Sniffer] scapy not installed: pip install scapy")
            sys.exit(1)

        self._running = True

        # Start processor + stats threads
        proc_thread  = threading.Thread(target=self._processor_thread, daemon=True)
        stats_thread = threading.Thread(target=self._stats_thread, daemon=True)
        proc_thread.start()
        stats_thread.start()

        print(f"\n{'='*60}")
        print(f"  PACKET SNIFFER")
        print(f"  Interface : {self.interface}")
        print(f"  SBI port  : {CFG['sbi_port']}")
        print(f"  Kafka     : {CFG['kafka_topic']}")
        print(f"  Dry run   : {CFG['dry_run']}")
        print(f"{'='*60}\n")
        print(f"  Sniffing... (Ctrl+C to stop)\n")

        # BPF filter — only SBI port traffic
        bpf = f"tcp port {CFG['sbi_port']}"

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf,
            prn=self._packet_callback,
            store=False,
        )
        sniffer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Stopping sniffer...")
            sniffer.stop()
            self._running = False
            time.sleep(1)
            pub = self.publisher.stats()
            print(f"\n  Final stats:")
            print(f"    Captured   : {self._stats['captured']}")
            print(f"    Processed  : {self._stats['processed']}")
            print(f"    Dropped    : {self._stats['dropped']}")
            print(f"    Published  : {pub['published']}")


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="5G SBI Packet Sniffer → Kafka Feature Publisher"
    )
    parser.add_argument("--interface", default=CFG["interface"],
                        help=f"Network interface to sniff (default: {CFG['interface']})")
    parser.add_argument("--broker", default=CFG["kafka_broker"],
                        help=f"Kafka broker address (default: {CFG['kafka_broker']})")
    parser.add_argument("--topic", default=CFG["kafka_topic"],
                        help=f"Kafka topic (default: {CFG['kafka_topic']})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print features to console instead of publishing to Kafka")
    args = parser.parse_args()

    CFG["interface"]   = args.interface
    CFG["kafka_broker"] = args.broker
    CFG["kafka_topic"] = args.topic
    CFG["dry_run"]     = args.dry_run

    publisher = KafkaPublisher(args.broker, args.topic, args.dry_run)
    sniffer   = PacketSniffer(args.interface, publisher)
    sniffer.start()
