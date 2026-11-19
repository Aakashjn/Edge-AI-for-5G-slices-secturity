"""
response_engine.py
==================
Layer 4 of the full pipeline.

Receives alerts and per-window scores from the DetectionEngine and:
  1. Isolates the slice with an OpenFlow drop rule via the Ryu ofctl_rest API.
     Every SliceShield rule carries a cookie (COOKIE_BASE + slice_id), so
     recovery removes ONLY our drop rule and never touches L2 forwarding flows.
  2. Re-admits the slice after N consecutive clean windows, or after the
     slice has been quiet (no traffic) for `quiet_readmit_s`.
  3. Writes every action to an append-only JSONL audit log.

Set SLICESHIELD_RYU_ENABLED=0 to run without a controller (actions are logged
as "simulated").
"""

import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import List

import requests

from features import SLICE_NAMES

CFG = {
    "ryu_enabled":        os.getenv("SLICESHIELD_RYU_ENABLED", "1") == "1",
    "ryu_url":            os.getenv("RYU_URL", "http://localhost:8080"),
    "dpid":               int(os.getenv("RYU_DPID", "1")),   # switch datapath id (s1 = 1)
    "max_isolations_min": 3,       # circuit breaker
    "clean_windows_req":  3,       # consecutive clean windows before re-admission
    "clean_threshold":    0.30,    # window prob below this = clean
    "quiet_readmit_s":    30.0,    # re-admit if no windows at all for this long
    "log_dir":            "logs",
    "audit_log":          "logs/response_audit.jsonl",
}

COOKIE_BASE = 0x55530000           # "SS" + slice id

# Slice 0 = switch port 1, slice 1 = port 2, slice 2 = port 3
SLICE_SDN_CONFIG = {
    0: {"port": 1, "priority": 200},
    1: {"port": 2, "priority": 210},
    2: {"port": 3, "priority": 220},
}

RESPONSE_PLAYBOOK = {
    "nosql_injection": {
        "immediate":   ["Block source IP at NRF ingress", "Rate-limit /nnrf-disc/ to 10 req/s",
                        "Enable MongoDB query validation"],
        "containment": ["Quarantine slice VLAN", "Freeze NRF VNF instance"],
        "recovery":    ["Re-validate all NF registrations", "Restore MongoDB ACLs"],
    },
    "subscriber_data_access": {
        "immediate":   ["Revoke OAuth2 tokens of requesting NF", "Audit UDM access logs"],
        "containment": ["Isolate slice"],
        "recovery":    ["Notify DPO of possible SUPI exposure"],
    },
    "default": {
        "immediate":   ["Block suspicious source", "Rate-limit affected endpoint"],
        "containment": ["Isolate slice"],
        "recovery":    ["Monitor for clean windows"],
    },
}


class CircuitBreaker:
    def __init__(self, max_per_min: int):
        self.max = max_per_min
        self.count = 0
        self.reset_at = time.time() + 60

    def allow(self) -> bool:
        if time.time() > self.reset_at:
            self.count, self.reset_at = 0, time.time() + 60
        if self.count >= self.max:
            return False
        self.count += 1
        return True


class AuditLog:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: dict):
        with self._lock, open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")


# ─────────────────────────────────────────────────────────────
# SDN CONTROLLER (Ryu ofctl_rest)
# ─────────────────────────────────────────────────────────────

class RyuController:
    def __init__(self, base_url: str, dpid: int, enabled: bool = True):
        self.base = base_url.rstrip("/")
        self.dpid = dpid
        self.enabled = enabled

    def _post(self, path: str, body: dict) -> dict:
        t0 = time.perf_counter()
        if not self.enabled:
            return {"status": "simulated", "latency_ms": 0.0}
        try:
            r = requests.post(f"{self.base}{path}", json=body, timeout=3)
            r.raise_for_status()
            status = "ok"
        except requests.RequestException as e:
            print(f"    [SDN] Ryu request failed: {e}")
            status = "failed"
        return {"status": status, "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}

    def isolate_slice(self, slice_id: int) -> dict:
        cfg = SLICE_SDN_CONFIG[slice_id]
        res = self._post("/stats/flowentry/add", {
            "dpid": self.dpid, "cookie": COOKIE_BASE + slice_id,
            "priority": cfg["priority"], "match": {"in_port": cfg["port"]},
            "actions": [],                       # empty action list = drop
        })
        res["status"] = "isolated" if res["status"] in ("ok", "simulated") else "failed"
        print(f"    [SDN] Slice {slice_id} drop rule on port {cfg['port']}: {res}")
        return res

    def restore_slice(self, slice_id: int) -> dict:
        res = self._post("/stats/flowentry/delete", {
            "dpid": self.dpid, "cookie": COOKIE_BASE + slice_id,
            "cookie_mask": 0xFFFFFFFFFFFFFFFF, "table_id": 0,
        })
        res["status"] = "restored" if res["status"] in ("ok", "simulated") else "failed"
        print(f"    [SDN] Slice {slice_id} drop rule removed: {res}")
        return res


# ─────────────────────────────────────────────────────────────
# RECOVERY MONITOR
# ─────────────────────────────────────────────────────────────

class RecoveryMonitor:
    def __init__(self, sdn: RyuController, audit: AuditLog):
        self.sdn = sdn
        self.audit = audit
        self.isolated = {}                    # slice_id -> isolated_at
        self.last_window = {}                 # slice_id -> ts of last window seen
        self.clean_counts = defaultdict(int)
        self._lock = threading.RLock()
        self.readmissions = 0
        threading.Thread(target=self._quiet_watchdog, daemon=True).start()

    def is_isolated(self, slice_id: int) -> bool:
        return slice_id in self.isolated

    def mark_isolated(self, slice_id: int):
        with self._lock:
            self.isolated[slice_id] = time.time()
            self.last_window[slice_id] = time.time()
            self.clean_counts[slice_id] = 0

    def record_window(self, slice_id: int, avg_prob: float):
        with self._lock:
            self.last_window[slice_id] = time.time()
            if slice_id not in self.isolated:
                return
            if avg_prob < CFG["clean_threshold"]:
                self.clean_counts[slice_id] += 1
                if self.clean_counts[slice_id] >= CFG["clean_windows_req"]:
                    self._readmit(slice_id, f"{CFG['clean_windows_req']} consecutive clean windows")
            else:
                self.clean_counts[slice_id] = 0

    def _quiet_watchdog(self):
        while True:
            time.sleep(1)
            now = time.time()
            with self._lock:
                for sid in list(self.isolated):
                    if now - self.last_window.get(sid, now) >= CFG["quiet_readmit_s"]:
                        self._readmit(sid, f"no traffic for {CFG['quiet_readmit_s']:.0f}s")

    def _readmit(self, slice_id: int, reason: str):
        isolated_at = self.isolated.pop(slice_id)
        self.clean_counts[slice_id] = 0
        self.readmissions += 1
        sdn_result = self.sdn.restore_slice(slice_id)
        print(f"  [RECOVERY] Slice {slice_id} re-admitted ({reason})")
        self.audit.write({
            "event": "slice_readmitted", "timestamp": datetime.now().isoformat(),
            "slice_id": slice_id, "slice_name": SLICE_NAMES[slice_id],
            "reason": reason, "isolated_for_s": round(time.time() - isolated_at, 1),
            "sdn": sdn_result,
        })


# ─────────────────────────────────────────────────────────────
# RESPONSE ENGINE
# ─────────────────────────────────────────────────────────────

class ResponseEngine:
    def __init__(self):
        self.audit = AuditLog(CFG["audit_log"])
        self.sdn = RyuController(CFG["ryu_url"], CFG["dpid"], CFG["ryu_enabled"])
        self.breaker = CircuitBreaker(CFG["max_isolations_min"])
        self.recovery = RecoveryMonitor(self.sdn, self.audit)
        self._stats = {"alerts_received": 0, "isolations": 0, "breaker_blocked": 0}
        mode = CFG["ryu_url"] if CFG["ryu_enabled"] else "disabled (simulated actions)"
        print(f"[Response] SDN controller: {mode}")

    def handle_window(self, slice_id: int, avg_prob: float):
        self.recovery.record_window(slice_id, avg_prob)

    def handle_alert(self, alert: dict):
        self._stats["alerts_received"] += 1
        slice_id = alert["slice_id"]
        if self.recovery.is_isolated(slice_id):
            return                              # already contained
        attack_type = self.classify_attack(alert.get("iocs", []))

        if not self.breaker.allow():
            self._stats["breaker_blocked"] += 1
            self.audit.write({"event": "isolation_suppressed", "timestamp": alert["timestamp"],
                              "slice_id": slice_id, "reason": "circuit breaker open",
                              "attack_type": attack_type})
            return

        t0 = time.perf_counter()
        sdn_result = self.sdn.isolate_slice(slice_id)
        isolate_ms = (time.perf_counter() - t0) * 1000
        if sdn_result["status"] == "isolated":
            self.recovery.mark_isolated(slice_id)
            self._stats["isolations"] += 1

        self.audit.write({
            "event":       "slice_isolated" if sdn_result["status"] == "isolated" else "isolation_failed",
            "timestamp":   alert["timestamp"],
            "slice_id":    slice_id,
            "slice_name":  alert.get("slice_name", SLICE_NAMES[slice_id]),
            "attack_type": attack_type,
            "avg_prob":    alert["avg_prob"],
            "iocs":        alert.get("iocs", []),
            "src_ips":     alert.get("src_ips", []),
            "playbook":    RESPONSE_PLAYBOOK[attack_type],
            "detect_ms":   alert["latency_ms"],
            "isolate_ms":  round(isolate_ms, 2),
            "total_ms":    round(alert["latency_ms"] + isolate_ms, 2),
            "sdn":         sdn_result,
            "raw_snippet": alert.get("raw_snippet", ""),
        })

    @staticmethod
    def classify_attack(iocs: List[str]) -> str:
        text = " ".join(iocs).lower()
        if "nosql" in text or "nrf discovery" in text:
            return "nosql_injection"
        if "supi" in text or "imsi" in text:
            return "subscriber_data_access"
        return "default"

    def stats(self) -> dict:
        s = self._stats.copy()
        s["readmissions"] = self.recovery.readmissions
        return s


def run() -> ResponseEngine:
    return ResponseEngine()
