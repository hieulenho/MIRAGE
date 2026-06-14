"""
MIRAGE - Layer 1: Multi-Stage Attack Modeling
============================================
Rule-based IF/ELSE stage classifier ánh xạ telemetry sang giai đoạn tấn công
theo framework MITRE ATT&CK.

Stages:
  0: Unknown
  1: Recon (Thăm dò)
  2: Initial Access (Truy cập ban đầu)
  3: Discovery (Khám phá)
  4: Lateral Movement (Di chuyển ngang)
  5: Credential Access (Truy cập thông tin xác thực)
  6: Collection (Thu thập)
  7: Exfiltration (Đánh cắp dữ liệu)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional
import time


class AttackStage(IntEnum):
    """Các giai đoạn tấn công theo MITRE ATT&CK."""
    UNKNOWN          = 0
    RECON            = 1   # Thăm dò
    INITIAL_ACCESS   = 2   # Truy cập ban đầu
    DISCOVERY        = 3   # Khám phá
    LATERAL_MOVEMENT = 4   # Di chuyển ngang
    CREDENTIAL_ACCESS= 5   # Truy cập thông tin xác thực
    COLLECTION       = 6   # Thu thập
    EXFILTRATION     = 7   # Đánh cắp dữ liệu


STAGE_NAMES = {
    AttackStage.UNKNOWN:           "Unknown",
    AttackStage.RECON:             "Recon",
    AttackStage.INITIAL_ACCESS:    "Initial Access",
    AttackStage.DISCOVERY:         "Discovery",
    AttackStage.LATERAL_MOVEMENT:  "Lateral Movement",
    AttackStage.CREDENTIAL_ACCESS: "Credential Access",
    AttackStage.COLLECTION:        "Collection",
    AttackStage.EXFILTRATION:      "Exfiltration",
}

# Map stage sang tactic MITRE ATT&CK
MITRE_TACTIC_MAP = {
    AttackStage.RECON:             "TA0043 - Reconnaissance",
    AttackStage.INITIAL_ACCESS:    "TA0001 - Initial Access",
    AttackStage.DISCOVERY:         "TA0007 - Discovery",
    AttackStage.LATERAL_MOVEMENT:  "TA0008 - Lateral Movement",
    AttackStage.CREDENTIAL_ACCESS: "TA0006 - Credential Access",
    AttackStage.COLLECTION:        "TA0009 - Collection",
    AttackStage.EXFILTRATION:      "TA0010 - Exfiltration",
}


@dataclass
class TelemetryEvent:
    """Sự kiện telemetry đầu vào từ mạng (được giả lập trong Version 1)."""
    timestamp: float
    source_host: str
    dest_host: str
    event_type: str       # "port_scan", "login_attempt", "smb_connect", "dns_query", etc.
    protocol: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    success: bool = True
    extra: Dict = field(default_factory=dict)


@dataclass
class StageEstimate:
    """Kết quả ước lượng giai đoạn tấn công cho một host."""
    host: str
    stage_distribution: Dict[AttackStage, float]  # Phân phối xác suất các stage
    dominant_stage: AttackStage
    confidence: float
    evidence: List[str]
    related_entities: List[str]
    timestamp: float


def _normalize(dist: Dict[AttackStage, float]) -> Dict[AttackStage, float]:
    """Chuẩn hóa phân phối xác suất."""
    total = sum(dist.values())
    if total <= 0:
        return {s: 0.0 for s in dist}
    return {s: v / total for s, v in dist.items()}


class AttackStageClassifier:
    """
    Lớp 1: Phân loại giai đoạn tấn công dựa trên luật (rule-based).
    
    Approach: rule + scoring theo chuỗi sự kiện.
    Version 1 dùng IF/ELSE đơn giản, mở rộng về sau với HMM hoặc sequence model.
    """

    def __init__(self):
        # Bộ đếm sự kiện theo host
        self._host_counters: Dict[str, Dict[str, int]] = {}
        # Lịch sử sự kiện
        self._event_history: Dict[str, List[TelemetryEvent]] = {}
        # Stage estimate hiện tại
        self._stage_estimates: Dict[str, StageEstimate] = {}

    def process_event(self, event: TelemetryEvent) -> StageEstimate:
        """
        Xử lý một sự kiện telemetry và cập nhật stage estimate.
        """
        host = event.source_host

        # Khởi tạo nếu chưa có
        if host not in self._host_counters:
            self._host_counters[host] = {
                "port_scans": 0,
                "login_attempts": 0,
                "login_failures": 0,
                "smb_connects": 0,
                "rdp_connects": 0,
                "dns_queries": 0,
                "file_accesses": 0,
                "data_transfers": 0,
                "credential_uses": 0,
                "external_connections": 0,
                "honey_credential_uses": 0,
                "decoy_touches": 0,
            }
            self._event_history[host] = []

        counters = self._host_counters[host]
        history = self._event_history[host]
        history.append(event)

        # ----- CẬP NHẬT COUNTERS THEO LOẠI SỰ KIỆN -----
        etype = event.event_type.lower()

        if etype == "port_scan":
            counters["port_scans"] += 1
        elif etype == "login_attempt":
            counters["login_attempts"] += 1
            if not event.success:
                counters["login_failures"] += 1
        elif etype == "smb_connect":
            counters["smb_connects"] += 1
        elif etype == "rdp_connect":
            counters["rdp_connects"] += 1
        elif etype == "dns_query":
            counters["dns_queries"] += 1
        elif etype == "file_access":
            counters["file_accesses"] += 1
        elif etype == "data_transfer":
            counters["data_transfers"] += 1
        elif etype == "credential_use":
            counters["credential_uses"] += 1
        elif etype == "external_connect":
            counters["external_connections"] += 1
        elif etype == "honey_credential_use":
            counters["honey_credential_uses"] += 1
            counters["credential_uses"] += 1
        elif etype == "decoy_touch":
            counters["decoy_touches"] += 1

        # ----- RULE-BASED STAGE SCORING -----
        scores: Dict[AttackStage, float] = {s: 0.0 for s in AttackStage}
        evidence: List[str] = []

        # --- RECON ---
        # IF port_scan > 0 THEN Recon
        if counters["port_scans"] > 0:
            scores[AttackStage.RECON] += 0.6
            if counters["port_scans"] > 3:
                scores[AttackStage.RECON] += 0.3
                evidence.append(f"Port scan > 3 ports ({counters['port_scans']} ports)")
            else:
                evidence.append(f"Port scan detected ({counters['port_scans']} ports)")

        # IF nhiều DNS query đến host lạ THEN Recon
        if counters["dns_queries"] > 5:
            scores[AttackStage.RECON] += 0.3
            evidence.append(f"High DNS query volume ({counters['dns_queries']})")

        # --- INITIAL ACCESS ---
        # IF login_failures cao THEN Initial Access
        if counters["login_failures"] > 2:
            scores[AttackStage.INITIAL_ACCESS] += 0.5
            evidence.append(f"Multiple login failures ({counters['login_failures']})")
        if counters["login_failures"] > 5:
            scores[AttackStage.INITIAL_ACCESS] += 0.4
            evidence.append("Brute force pattern detected")

        # IF honey credential được dùng THEN Initial Access/Credential
        if counters["honey_credential_uses"] > 0:
            scores[AttackStage.INITIAL_ACCESS] += 0.7
            scores[AttackStage.CREDENTIAL_ACCESS] += 0.8
            evidence.append(f"HONEY CREDENTIAL TRIGGERED — {counters['honey_credential_uses']} use(s)")

        # --- DISCOVERY ---
        # IF quét > 3 cổng THEN Discovery (nếu đã vào mạng)
        if counters["port_scans"] > 3 and counters["login_attempts"] > 0:
            scores[AttackStage.DISCOVERY] += 0.7
            evidence.append("Internal port scan after login → Discovery")

        # IF SMB connect > 2 THEN Discovery (dò SMB shares)
        if counters["smb_connects"] > 2:
            scores[AttackStage.DISCOVERY] += 0.6
            evidence.append(f"SMB share enumeration ({counters['smb_connects']} connects)")

        # IF decoy được chạm tới THEN Discovery rất rõ
        if counters["decoy_touches"] > 0:
            scores[AttackStage.DISCOVERY] += 1.0
            evidence.append(f"DECOY TOUCHED — attacker is exploring ({counters['decoy_touches']}x)")

        # --- LATERAL MOVEMENT ---
        # IF RDP hoặc SMB kết nối tới nhiều máy THEN Lateral Movement
        if counters["rdp_connects"] > 1 or (counters["smb_connects"] > 3):
            scores[AttackStage.LATERAL_MOVEMENT] += 0.7
            evidence.append(f"Multi-host connection pattern (RDP={counters['rdp_connects']}, SMB={counters['smb_connects']})")

        # IF credential_use cao sau discovery THEN Lateral Movement
        if counters["credential_uses"] > 1 and counters["smb_connects"] > 1:
            scores[AttackStage.LATERAL_MOVEMENT] += 0.6
            evidence.append("Credential reuse across hosts → Lateral Movement")

        # --- CREDENTIAL ACCESS ---
        # IF credential_use bất thường
        if counters["credential_uses"] > 3:
            scores[AttackStage.CREDENTIAL_ACCESS] += 0.5
            evidence.append(f"High credential use ({counters['credential_uses']})")

        # --- COLLECTION ---
        # IF file_access cao THEN Collection
        if counters["file_accesses"] > 5:
            scores[AttackStage.COLLECTION] += 0.7
            evidence.append(f"Mass file access ({counters['file_accesses']} files)")

        if counters["data_transfers"] > 0:
            scores[AttackStage.COLLECTION] += 0.5
            evidence.append(f"Data transfer initiated ({counters['data_transfers']})")

        # --- EXFILTRATION ---
        # IF external_connection + data_transfer THEN Exfiltration
        if counters["external_connections"] > 0 and counters["data_transfers"] > 0:
            scores[AttackStage.EXFILTRATION] += 0.9
            evidence.append("External transfer detected → Exfiltration")

        if counters["external_connections"] > 2:
            scores[AttackStage.EXFILTRATION] += 0.4
            evidence.append(f"Multiple external connections ({counters['external_connections']})")

        # ----- TÍNH PHÂN PHỐI -----
        scores[AttackStage.UNKNOWN] = max(0.0, 0.5 - sum(scores.values()) * 0.1)
        dist = _normalize(scores)

        # Tính stage chiếm ưu thế
        dominant = max(dist, key=lambda s: dist[s])
        confidence = dist[dominant]

        # Entity liên quan
        related = []
        if event.username:
            related.append(f"user:{event.username}")
        if event.dest_host:
            related.append(f"dest:{event.dest_host}")

        estimate = StageEstimate(
            host=host,
            stage_distribution=dist,
            dominant_stage=dominant,
            confidence=confidence,
            evidence=evidence,
            related_entities=related,
            timestamp=event.timestamp,
        )
        self._stage_estimates[host] = estimate
        return estimate

    def get_estimate(self, host: str) -> Optional[StageEstimate]:
        """Lấy ước lượng stage hiện tại cho một host."""
        return self._stage_estimates.get(host)

    def get_all_estimates(self) -> Dict[str, StageEstimate]:
        """Lấy tất cả ước lượng stage."""
        return dict(self._stage_estimates)

    def reset_host(self, host: str) -> None:
        """Reset trạng thái của một host."""
        self._host_counters.pop(host, None)
        self._event_history.pop(host, None)
        self._stage_estimates.pop(host, None)

    def summary(self) -> str:
        """In tóm tắt trạng thái hiện tại."""
        lines = ["=" * 60, "MIRAGE Layer 1 — Attack Stage Summary", "=" * 60]
        for host, est in self._stage_estimates.items():
            lines.append(f"\nHost: {host}")
            lines.append(f"  Dominant Stage: [{STAGE_NAMES[est.dominant_stage]}] ({est.confidence:.1%})")
            lines.append(f"  MITRE Tactic: {MITRE_TACTIC_MAP.get(est.dominant_stage, 'N/A')}")
            top3 = sorted(est.stage_distribution.items(), key=lambda x: -x[1])[:3]
            lines.append("  Stage Distribution (Top 3):")
            for stage, prob in top3:
                if prob > 0.01:
                    lines.append(f"    {STAGE_NAMES[stage]:20s}: {prob:.2%}")
            if est.evidence:
                lines.append("  Evidence:")
                for e in est.evidence[-3:]:  # Hiện 3 evidence gần nhất
                    lines.append(f"    • {e}")
        return "\n".join(lines)


def simulate_attack_telemetry(scenario: str = "lateral_movement") -> List[TelemetryEvent]:
    """
    Tạo chuỗi sự kiện telemetry giả lập cho demo.
    Dùng trong Version 1 thay vì đọc log thật.
    """
    t = time.time()
    events: List[TelemetryEvent] = []

    if scenario == "lateral_movement":
        # Kịch bản: attacker đang lateral movement
        events = [
            TelemetryEvent(t+0,  "attacker_pc", "192.168.1.10", "port_scan", port=445),
            TelemetryEvent(t+1,  "attacker_pc", "192.168.1.10", "port_scan", port=3389),
            TelemetryEvent(t+2,  "attacker_pc", "192.168.1.10", "port_scan", port=22),
            TelemetryEvent(t+3,  "attacker_pc", "192.168.1.10", "port_scan", port=80),
            TelemetryEvent(t+4,  "attacker_pc", "192.168.1.1",  "login_attempt", username="admin", success=False),
            TelemetryEvent(t+5,  "attacker_pc", "192.168.1.1",  "login_attempt", username="admin", success=False),
            TelemetryEvent(t+6,  "attacker_pc", "192.168.1.1",  "login_attempt", username="admin", success=True),
            TelemetryEvent(t+7,  "attacker_pc", "192.168.1.5",  "smb_connect"),
            TelemetryEvent(t+8,  "attacker_pc", "192.168.1.6",  "smb_connect"),
            TelemetryEvent(t+9,  "attacker_pc", "192.168.1.7",  "smb_connect"),
            TelemetryEvent(t+10, "attacker_pc", "192.168.1.8",  "rdp_connect"),
            TelemetryEvent(t+11, "attacker_pc", "192.168.1.9",  "rdp_connect"),
            TelemetryEvent(t+12, "attacker_pc", "192.168.1.10", "credential_use", username="svc_account"),
        ]
    elif scenario == "exfiltration":
        events = [
            TelemetryEvent(t+0, "insider", "db_server", "credential_use", username="db_admin"),
            TelemetryEvent(t+1, "insider", "db_server", "file_access"),
            TelemetryEvent(t+2, "insider", "db_server", "file_access"),
            TelemetryEvent(t+3, "insider", "db_server", "file_access"),
            TelemetryEvent(t+4, "insider", "db_server", "file_access"),
            TelemetryEvent(t+5, "insider", "db_server", "file_access"),
            TelemetryEvent(t+6, "insider", "db_server", "file_access"),
            TelemetryEvent(t+7, "insider", "8.8.8.8",   "data_transfer"),
            TelemetryEvent(t+8, "insider", "8.8.8.8",   "external_connect"),
            TelemetryEvent(t+9, "insider", "1.2.3.4",   "external_connect"),
            TelemetryEvent(t+10,"insider", "5.6.7.8",   "external_connect"),
        ]
    elif scenario == "honey_trap":
        events = [
            TelemetryEvent(t+0, "recon_host", "honeypot", "port_scan"),
            TelemetryEvent(t+1, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+2, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+3, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+4, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+5, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+6, "recon_host", "honeypot", "dns_query"),
            TelemetryEvent(t+7, "recon_host", "fake_db",  "honey_credential_use", username="sa_backup"),
            TelemetryEvent(t+8, "recon_host", "fake_db",  "decoy_touch"),
        ]
    return events


if __name__ == "__main__":
    classifier = AttackStageClassifier()
    print("Testing Layer 1 — Lateral Movement Scenario")
    for event in simulate_attack_telemetry("lateral_movement"):
        est = classifier.process_event(event)
    print(classifier.summary())

    print("\n\nTesting Layer 1 — Honey Trap Scenario")
    classifier2 = AttackStageClassifier()
    for event in simulate_attack_telemetry("honey_trap"):
        est = classifier2.process_event(event)
    print(classifier2.summary())
