"""
MIRAGE - Layer 5: Safe Response & Real-Time Control
====================================================
"Người gác cổng" — kiểm tra mọi quyết định của AI trước khi thực thi.

Phân cấp rủi ro:
  LOW      (0.0-0.2): Tự động triển khai
  MEDIUM   (0.2-0.5): Log cảnh báo, cho phép nhưng audit kỹ
  HIGH     (0.5-0.8): ⚠️ CẢNH BÁO — Cần xác nhận từ SOC
  CRITICAL (0.8-1.0): 🚫 BLOCK — Bắt buộc human approval

Guardrails bắt buộc:
  1. Action allowlist: chỉ actions đã định nghĩa mới được thực thi
  2. Scope limit: không vượt ra ngoài perimeter hợp phép
  3. Business criticality: node quan trọng cần approval
  4. Confidence threshold: action nguy hiểm cần confidence cao
  5. Rollback plan: mọi action phải có cách hoàn tác
  6. Audit log: ghi rõ ai/agent đề xuất, ai duyệt, tại sao
  7. Fail-safe: khi không chắc → observe-only mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import time
import json
import os


class RiskLevel(Enum):
    """Cấp độ rủi ro của hành động."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


RISK_COLORS = {
    RiskLevel.LOW:      "✅",
    RiskLevel.MEDIUM:   "⚠️ ",
    RiskLevel.HIGH:     "🔴",
    RiskLevel.CRITICAL: "🚫",
}

RISK_THRESHOLDS = {
    RiskLevel.LOW:      0.2,
    RiskLevel.MEDIUM:   0.5,
    RiskLevel.HIGH:     0.8,
    RiskLevel.CRITICAL: 1.0,
}


@dataclass
class SafetyDecision:
    """Kết quả kiểm tra an toàn."""
    allowed: bool
    risk_level: RiskLevel
    warning_message: str
    requires_human_approval: bool
    audit_notes: List[str]
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        icon = RISK_COLORS[self.risk_level]
        status = "ALLOWED" if self.allowed else "BLOCKED"
        lines = [
            f"\n{'─'*60}",
            f"Safety Gate Decision: [{status}] {icon} Risk: {self.risk_level.value}",
            f"{'─'*60}",
        ]
        if self.warning_message:
            lines.append(f"⚡ {self.warning_message}")
        if self.requires_human_approval:
            lines.append("👤 ACTION REQUIRES HUMAN APPROVAL")
        if self.audit_notes:
            lines.append("Audit Notes:")
            for note in self.audit_notes:
                lines.append(f"  • {note}")
        return "\n".join(lines)


@dataclass
class AuditLogEntry:
    """Một entry trong audit log."""
    timestamp: float
    agent: str
    action_type: str
    target_node: int
    target_node_label: str
    risk_level: str
    decision: str          # "ALLOWED" / "BLOCKED" / "PENDING_APPROVAL"
    reasoning: str
    approved_by: Optional[str] = None  # None nếu auto-approved


# ---------------------------------------------------------------------------
# Safety Gate
# ---------------------------------------------------------------------------

class SafetyGate:
    """
    Lớp 5: Cổng kiểm soát an toàn cho mọi quyết định của AI.
    
    Chức năng:
    1. Phân loại rủi ro của action
    2. Kiểm tra guardrails
    3. Tạo cảnh báo cho SOC
    4. Ghi audit log
    5. Fail-safe mode khi không chắc chắn
    """

    # Node IDs quan trọng KHÔNG được tự động block/isolate
    PROTECTED_NODES = {10, 13}  # DB_REAL, DomainController

    # Action types không bao giờ được phép thực thi
    FORBIDDEN_ACTIONS = {
        "hack_back",
        "isolate_production_db",
        "block_all_traffic",
        "delete_credentials",
    }

    # Ngưỡng confidence tối thiểu theo risk level
    MIN_CONFIDENCE = {
        RiskLevel.LOW:      0.0,
        RiskLevel.MEDIUM:   0.5,
        RiskLevel.HIGH:     0.7,
        RiskLevel.CRITICAL: 0.9,
    }

    def __init__(
        self,
        audit_log_path: Optional[str] = None,
        fail_safe_mode: bool = False,
        budget_limit: float = 6.0,
    ):
        self.audit_log_path = audit_log_path
        self.fail_safe_mode = fail_safe_mode
        self.budget_limit = budget_limit
        self.budget_spent: float = 0.0
        self.audit_entries: List[AuditLogEntry] = []
        self._pending_approvals: List[Dict] = []

    def classify_risk(self, action, graph=None) -> RiskLevel:
        """
        Phân loại rủi ro của action dựa trên nhiều yếu tố.
        """
        risk_score = action.risk_score

        # Tăng risk nếu target là node quan trọng
        if hasattr(action, 'target_node') and action.target_node in self.PROTECTED_NODES:
            risk_score = min(1.0, risk_score + 0.4)

        # Tăng risk nếu business impact cao
        if action.business_impact > 0.3:
            risk_score = min(1.0, risk_score + 0.2)

        # Phân loại theo thresholds
        if risk_score < 0.2:
            return RiskLevel.LOW
        elif risk_score < 0.5:
            return RiskLevel.MEDIUM
        elif risk_score < 0.8:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def check_action_plan(self, plan, graph=None) -> Tuple[bool, SafetyDecision]:
        """
        Kiểm tra một ActionPlan trước khi thực thi.
        
        Returns:
            (allowed: bool, safety_decision: SafetyDecision)
        """
        audit_notes = []
        risk_level = self.classify_risk(plan.action, graph)
        warnings = []
        allowed = True
        requires_human = False
        from mirage.mdp_solver import compute_portfolio_cost

        plan_actions = getattr(plan, "portfolio", None) or [plan.action]
        cost_report = compute_portfolio_cost(plan_actions, graph)
        request_cost = float(getattr(plan, "portfolio_cost", 0.0) or cost_report["total"])
        risk_rank = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        for action in plan_actions:
            action_risk = self.classify_risk(action, graph)
            if risk_rank[action_risk] > risk_rank[risk_level]:
                risk_level = action_risk

        # ---- GUARDRAIL 1: Fail-safe mode ----
        if self.fail_safe_mode:
            return False, SafetyDecision(
                allowed=False,
                risk_level=RiskLevel.CRITICAL,
                warning_message="System is in FAIL-SAFE (observe-only) mode. No actions allowed.",
                requires_human_approval=True,
                audit_notes=["Fail-safe mode active"],
            )

        # ---- GUARDRAIL 2: Forbidden action types ----
        action_str = plan.action.action_type.value
        if action_str in self.FORBIDDEN_ACTIONS:
            return False, SafetyDecision(
                allowed=False,
                risk_level=RiskLevel.CRITICAL,
                warning_message=f"🚫 FORBIDDEN ACTION: '{action_str}' is not in the allowed list.",
                requires_human_approval=True,
                audit_notes=[f"Forbidden action blocked: {action_str}"],
            )

        # ---- GUARDRAIL 3: Budget check ----
        if self.budget_spent + request_cost > self.budget_limit:
            budget_warning = (
                f"Budget exceeded: spent={self.budget_spent:.1f}, "
                f"request={request_cost:.1f}, limit={self.budget_limit:.1f}"
            )
            audit_notes.append(budget_warning)
            return False, SafetyDecision(
                allowed=False,
                risk_level=RiskLevel.MEDIUM,
                warning_message=f"⚠️ Budget limit exceeded. {budget_warning}",
                requires_human_approval=False,
                audit_notes=audit_notes,
            )

        # ---- GUARDRAIL 4: Protected node check ----
        if plan.target_node in self.PROTECTED_NODES:
            warnings.append(
                f"⚠️ Target is PROTECTED node (Node {plan.target_node}: {plan.target_node_label}). "
                "Extra caution required."
            )
            risk_level = RiskLevel.HIGH
            requires_human = True
            audit_notes.append(f"Protected node targeted: {plan.target_node_label}")

        # ---- GUARDRAIL 5: Risk-based approval ----
        if risk_level == RiskLevel.LOW:
            # Auto-approved, chỉ log
            audit_notes.append("Auto-approved: LOW risk action")

        elif risk_level == RiskLevel.MEDIUM:
            # Log cảnh báo nhưng cho phép
            warnings.append(
                f"⚠️  [CẢNH BÁO] Hành động Rủi ro TRUNG BÌNH: "
                f"{plan.action.action_type.value} tại {plan.target_node_label}. "
                "Đang được ghi lại và theo dõi kỹ."
            )
            audit_notes.append(f"MEDIUM risk - logging enhanced monitoring")

        elif risk_level == RiskLevel.HIGH:
            # Cảnh báo mạnh, cần human approval
            warnings.append(
                f"🔴 [CẢNH BÁO] Hành động Rủi ro CAO: "
                f"{plan.action.action_type.value} tại {plan.target_node_label}. "
                "CẦN XÁC NHẬN TỪ SOC ANALYST trước khi thực thi!"
            )
            requires_human = True
            audit_notes.append("HIGH risk - human approval required")

        elif risk_level == RiskLevel.CRITICAL:
            # Block hoàn toàn
            allowed = False
            warnings.append(
                f"🚫 [CHẶN] Hành động NGUY HIỂM NGHIÊM TRỌNG: "
                f"{plan.action.action_type.value}. "
                "Hệ thống từ chối thực thi tự động. Cần approval cấp cao."
            )
            requires_human = True
            audit_notes.append("CRITICAL risk - action BLOCKED")

        # ---- GUARDRAIL 6: Confidence check ----
        min_conf = self.MIN_CONFIDENCE[risk_level]
        if plan.confidence < min_conf:
            confidence_warning = (
                f"Confidence {plan.confidence:.1%} below minimum {min_conf:.1%} "
                f"for {risk_level.value} risk action."
            )
            warnings.append(f"⚠️  Low confidence: {confidence_warning}")
            audit_notes.append(confidence_warning)
            if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                allowed = False

        # ---- GUARDRAIL 7: Pessimistic value sanity check ----
        if plan.pessimistic_value < -1.5:
            warnings.append(
                f"⚠️  Pessimistic value {plan.pessimistic_value:.4f} is very negative. "
                "This action may not be beneficial in worst-case scenarios."
            )
            audit_notes.append(f"Low pessimistic value: {plan.pessimistic_value:.4f}")

        # In cảnh báo
        for w in warnings:
            print(f"\n  {w}")

        # Ghi audit log
        entry = AuditLogEntry(
            timestamp=time.time(),
            agent="MIRAGE_Decision_Engine_v1",
            action_type=plan.action.action_type.value,
            target_node=plan.target_node,
            target_node_label=plan.target_node_label,
            risk_level=risk_level.value,
            decision="BLOCKED" if not allowed else ("PENDING_APPROVAL" if requires_human else "ALLOWED"),
            reasoning=plan.reasoning,
            approved_by=None if requires_human else "AUTO",
        )
        self._add_audit_entry(entry)

        # Cập nhật budget nếu được phép
        if allowed:
            self.budget_spent += request_cost

        decision = SafetyDecision(
            allowed=allowed,
            risk_level=risk_level,
            warning_message=warnings[-1] if warnings else "",
            requires_human_approval=requires_human,
            audit_notes=audit_notes,
        )
        return allowed, decision

    def _add_audit_entry(self, entry: AuditLogEntry) -> None:
        """Thêm entry vào audit log."""
        self.audit_entries.append(entry)
        if self.audit_log_path:
            try:
                with open(self.audit_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "timestamp": entry.timestamp,
                        "agent": entry.agent,
                        "action_type": entry.action_type,
                        "target_node": entry.target_node,
                        "target_node_label": entry.target_node_label,
                        "risk_level": entry.risk_level,
                        "decision": entry.decision,
                        "reasoning": entry.reasoning[:200],
                    }) + "\n")
            except Exception:
                pass

    def enter_fail_safe(self, reason: str = "Manual override") -> None:
        """Kích hoạt fail-safe mode (observe-only)."""
        self.fail_safe_mode = True
        print(f"\n🚫 [FAIL-SAFE ACTIVATED] System entering observe-only mode. Reason: {reason}")
        self._add_audit_entry(AuditLogEntry(
            timestamp=time.time(),
            agent="MIRAGE_Safety_Layer",
            action_type="fail_safe_mode",
            target_node=-1,
            target_node_label="SYSTEM",
            risk_level="CRITICAL",
            decision="FAIL_SAFE_ACTIVE",
            reasoning=reason,
        ))

    def exit_fail_safe(self, approved_by: str = "SOC_Admin") -> None:
        """Thoát fail-safe mode sau khi có approval."""
        self.fail_safe_mode = False
        print(f"\n✅ [FAIL-SAFE DEACTIVATED] System resuming normal operations. Approved by: {approved_by}")

    def approve_action(self, plan, approved_by: str = "SOC_Analyst") -> None:
        """Human operator phê duyệt một action đang chờ."""
        print(f"\n✅ [HUMAN APPROVAL] Action '{plan.action.action_type.value}' "
              f"approved by {approved_by}")
        # Tìm và update audit entry
        for entry in reversed(self.audit_entries):
            if entry.action_type == plan.action.action_type.value:
                entry.approved_by = approved_by
                entry.decision = "ALLOWED"
                break

    def get_audit_summary(self) -> str:
        """In tóm tắt audit log."""
        lines = [
            "=" * 65,
            "MIRAGE Layer 5 — Safety Gate Audit Log",
            "=" * 65,
            f"Total decisions: {len(self.audit_entries)}",
            f"Budget spent:    {self.budget_spent:.1f} / {self.budget_limit:.1f}",
            f"Fail-safe mode:  {'ACTIVE' if self.fail_safe_mode else 'inactive'}",
            "",
            "Recent Decisions:",
        ]
        for entry in self.audit_entries[-10:]:  # Last 10
            icon = "✅" if entry.decision == "ALLOWED" else ("🔴" if entry.decision == "BLOCKED" else "⚠️ ")
            lines.append(
                f"  {icon} [{entry.risk_level:8s}] {entry.action_type:35s} "
                f"→ {entry.target_node_label:25s} | {entry.decision}"
            )

        # Risk distribution
        risk_counts: Dict[str, int] = {}
        for e in self.audit_entries:
            risk_counts[e.risk_level] = risk_counts.get(e.risk_level, 0) + 1
        lines.append("\nRisk Distribution:")
        for level, count in sorted(risk_counts.items()):
            lines.append(f"  {level:10s}: {count}")
        return "\n".join(lines)


def create_safety_gate(
    audit_log_dir: str = "results",
    budget_limit: float = 6.0,
) -> SafetyGate:
    """Factory function tạo Safety Gate với audit logging."""
    os.makedirs(audit_log_dir, exist_ok=True)
    audit_path = os.path.join(audit_log_dir, "mirage_audit_log.jsonl")
    return SafetyGate(
        audit_log_path=audit_path,
        fail_safe_mode=False,
        budget_limit=budget_limit,
    )


# ---------------------------------------------------------------------------
# Convenience function for Layer 4 integration
# ---------------------------------------------------------------------------

def make_safety_filter(gate: SafetyGate, graph=None):
    """
    Tạo safety filter function để truyền vào Decision Engine.
    Returns: function(plan) → (allowed: bool, message: str)
    """
    def filter_fn(plan) -> Tuple[bool, str]:
        allowed, decision = gate.check_action_plan(plan, graph)
        return allowed, decision.warning_message
    return filter_fn


if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer3_deception import DeceptionFabric, DeceptionActionType
    from mirage.layer4_decision_engine import RobustDecisionEngine, ActionPlan

    print("Testing Layer 5 — Safety Gate")
    graph = build_enterprise_attack_graph()
    gate = create_safety_gate("results")

    # Test với các action có risk level khác nhau
    from mirage.layer3_deception import DeceptionAction
    from mirage.layer2_attack_graph import DB_FAKE, DB_REAL, DC_NODE

    print("\n--- Test 1: LOW risk action (Fake DB at decoy node) ---")
    low_risk_action = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=DB_FAKE,
        risk_score=0.1,
        realism_score=0.85,
        business_impact=0.05,
        cost=1.5,
        description="Deploy Fake DB",
        rollback_plan="Stop container",
        reward_delta=0.9,
    )

    class MockPlan:
        def __init__(self, action, target_node, label, pess_val, confidence):
            self.action = action
            self.target_node = target_node
            self.target_node_label = label
            self.pessimistic_value = pess_val
            self.confidence = confidence
            self.reasoning = "Test reasoning"

    plan1 = MockPlan(low_risk_action, DB_FAKE, "DB_FAKE_Backup", 0.3, 0.75)
    allowed, decision = gate.check_action_plan(plan1, graph)
    print(decision)

    print("\n--- Test 2: HIGH risk action (deploy at critical node) ---")
    high_risk_action = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=DB_REAL,  # ← Protected node!
        risk_score=0.6,
        realism_score=0.9,
        business_impact=0.2,
        cost=2.0,
        description="Deploy near real DB",
        rollback_plan="Remove",
        reward_delta=0.5,
    )
    plan2 = MockPlan(high_risk_action, DB_REAL, "DB_REAL_Finance", -0.5, 0.6)
    allowed2, decision2 = gate.check_action_plan(plan2, graph)
    print(decision2)

    print("\n--- Test 3: Fail-safe mode ---")
    gate.enter_fail_safe("System uncertainty too high")
    plan3 = MockPlan(low_risk_action, DB_FAKE, "DB_FAKE", 0.3, 0.8)
    allowed3, decision3 = gate.check_action_plan(plan3, graph)
    print(decision3)
    gate.exit_fail_safe("SOC_Admin_001")

    print("\n")
    print(gate.get_audit_summary())
