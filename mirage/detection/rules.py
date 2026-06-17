"""Explainable deterministic detection rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from mirage.detection.utils import stable_id
from mirage.domain.schemas import FeatureRecord, RuleMatch, SecurityEvent


@dataclass(frozen=True)
class DetectionContext:
    """Context supplied to detection rules."""

    entity_ids: list[str]
    features: dict[str, FeatureRecord]
    recent_evidence_count: int = 0
    approved_admin_hosts: tuple[str, ...] = ()
    approved_service_accounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectionRule:
    """Configurable detection rule wrapper."""

    rule_id: str
    name: str
    description: str
    enabled: bool
    severity: str
    stage_hints: tuple[str, ...]
    temporal_window_seconds: int
    score: float
    confidence: float
    evidence_ttl_seconds: int
    technique_ids: tuple[str, ...]
    evaluator: Callable[[SecurityEvent, DetectionContext], bool]
    suppresses: bool = False

    def evaluate(
        self,
        event: SecurityEvent,
        context: DetectionContext,
    ) -> RuleMatch | None:
        """Evaluate this rule against an event and context."""
        if not self.enabled or not self.evaluator(event, context):
            return None
        match_id = stable_id(self.rule_id, [event.event_id, *context.entity_ids])
        return RuleMatch(
            match_id=match_id,
            rule_id=self.rule_id,
            rule_name=self.name,
            event_ids=[event.event_id],
            entity_ids=context.entity_ids,
            stage_hints=list(self.stage_hints),
            score=self.score,
            confidence=min(1.0, self.confidence * event.confidence),
            severity=self.severity,
            description=self.description,
            feature_names=[
                name
                for name, feature in context.features.items()
                if bool(feature.value)
            ],
            suppresses=self.suppresses,
            expires_at=event.event_time + timedelta(seconds=self.evidence_ttl_seconds),
            technique_ids=list(self.technique_ids or event.technique_ids),
        )


class RuleEngine:
    """Evaluate built-in explainable rules with config overrides."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.rules = self._build_rules()

    def evaluate_event(
        self,
        event: SecurityEvent,
        context: DetectionContext,
    ) -> list[RuleMatch]:
        """Evaluate all enabled rules for one event."""
        matches = [
            match
            for rule in self.rules
            if (match := rule.evaluate(event, context)) is not None
        ]
        deception = any(match.rule_id == "R008_DECEPTION_INTERACTION" for match in matches)
        suppressions = [match for match in matches if match.suppresses]
        if suppressions and not deception:
            suppressed = []
            for match in matches:
                if match.suppresses:
                    suppressed.append(match)
                else:
                    damped = match.model_copy(
                        update={
                            "score": max(0.0, match.score * 0.35),
                            "confidence": max(0.0, match.confidence * 0.6),
                            "description": (
                                match.description
                                + " Suppressed by benign administrative context."
                            ),
                        }
                    )
                    suppressed.append(damped)
            matches = suppressed
        return sorted(matches, key=lambda match: match.rule_id)

    def evaluate_entity(
        self,
        entity_id: str,
        reference_time,
    ) -> list[RuleMatch]:
        """Reserved entity-wide rule hook; event-local rules run in V1."""
        return []

    def _rule_enabled(self, rule_id: str) -> bool:
        rules_config = self.config.get("rules", {})
        return bool(rules_config.get(rule_id, {}).get("enabled", True))

    def _weight(self, rule_id: str, default: float) -> float:
        rules_config = self.config.get("rules", {})
        return float(rules_config.get(rule_id, {}).get("score", default))

    def _build_rules(self) -> list[DetectionRule]:
        return [
            DetectionRule(
                rule_id="R001_SUSPICIOUS_SCRIPT",
                name="Suspicious PowerShell or script interpreter",
                description=(
                    "Script interpreter with encoded, download, or hidden "
                    "execution indicators."
                ),
                enabled=self._rule_enabled("R001_SUSPICIOUS_SCRIPT"),
                severity="high",
                stage_hints=("execution", "defense_evasion", "command_and_control"),
                temporal_window_seconds=300,
                score=self._weight("R001_SUSPICIOUS_SCRIPT", 0.65),
                confidence=0.85,
                evidence_ttl_seconds=3600,
                technique_ids=("T1059", "T1059.001"),
                evaluator=lambda event, ctx: bool(
                    ctx.features["is_script_interpreter"].value
                    and (
                        ctx.features["contains_encoded_command"].value
                        or ctx.features["contains_download_behavior"].value
                        or ctx.features["uses_hidden_execution"].value
                    )
                ),
            ),
            DetectionRule(
                rule_id="R002_INTERNAL_DISCOVERY_BURST",
                name="Internal network discovery burst",
                description="One entity contacted many internal hosts or SMB endpoints quickly.",
                enabled=self._rule_enabled("R002_INTERNAL_DISCOVERY_BURST"),
                severity="medium",
                stage_hints=("discovery",),
                temporal_window_seconds=300,
                score=self._weight("R002_INTERNAL_DISCOVERY_BURST", 0.55),
                confidence=0.75,
                evidence_ttl_seconds=1800,
                technique_ids=("T1046",),
                evaluator=lambda event, ctx: bool(
                    event.event_type == "network_connection"
                    and ctx.features["is_internal_network_connection"].value
                    and (
                        int(ctx.features["unique_destination_hosts_300s"].value) >= 5
                        or int(ctx.features["smb_connection_burst_300s"].value) >= 5
                    )
                ),
            ),
            DetectionRule(
                rule_id="R003_SMB_LATERAL_PATTERN",
                name="SMB lateral movement pattern",
                description="SMB burst with credential or prior suspicious context.",
                enabled=self._rule_enabled("R003_SMB_LATERAL_PATTERN"),
                severity="high",
                stage_hints=("credential_access", "lateral_movement"),
                temporal_window_seconds=900,
                score=self._weight("R003_SMB_LATERAL_PATTERN", 0.65),
                confidence=0.8,
                evidence_ttl_seconds=3600,
                technique_ids=("T1021.002",),
                evaluator=lambda event, ctx: bool(
                    ctx.features["is_smb_connection"].value
                    and (
                        int(ctx.features["smb_connection_burst_900s"].value) >= 3
                        or ctx.features["credential_then_lateral_activity_900s"].value
                        or ctx.recent_evidence_count > 0
                    )
                ),
            ),
            DetectionRule(
                rule_id="R004_AUTH_SPRAY",
                name="Authentication spray",
                description="Many failed authentications in a short temporal window.",
                enabled=self._rule_enabled("R004_AUTH_SPRAY"),
                severity="high",
                stage_hints=("credential_access", "initial_access"),
                temporal_window_seconds=300,
                score=self._weight("R004_AUTH_SPRAY", 0.7),
                confidence=0.82,
                evidence_ttl_seconds=3600,
                technique_ids=("T1110",),
                evaluator=lambda event, ctx: bool(
                    event.event_type == "authentication_failure"
                    and int(ctx.features["failed_login_count_300s"].value) >= 5
                ),
            ),
            DetectionRule(
                rule_id="R005_SUCCESS_AFTER_FAILURES",
                name="Successful authentication after failures",
                description="A success followed repeated failed authentications.",
                enabled=self._rule_enabled("R005_SUCCESS_AFTER_FAILURES"),
                severity="high",
                stage_hints=("initial_access", "credential_access", "lateral_movement"),
                temporal_window_seconds=900,
                score=self._weight("R005_SUCCESS_AFTER_FAILURES", 0.75),
                confidence=0.82,
                evidence_ttl_seconds=3600,
                technique_ids=("T1110",),
                evaluator=lambda event, ctx: bool(
                    event.event_type == "authentication_success"
                    and ctx.features["successful_login_after_failures_900s"].value
                ),
            ),
            DetectionRule(
                rule_id="R006_IDENTITY_FANOUT",
                name="Identity fan-out",
                description="One identity or source touches many assets quickly.",
                enabled=self._rule_enabled("R006_IDENTITY_FANOUT"),
                severity="medium",
                stage_hints=("discovery", "lateral_movement"),
                temporal_window_seconds=900,
                score=self._weight("R006_IDENTITY_FANOUT", 0.55),
                confidence=0.72,
                evidence_ttl_seconds=1800,
                technique_ids=("T1087",),
                evaluator=lambda event, ctx: bool(
                    int(ctx.features["identity_or_asset_fanout_900s"].value) >= 5
                    and not self._is_approved_service(event)
                ),
            ),
            DetectionRule(
                rule_id="R007_CREDENTIAL_TO_REMOTE",
                name="Credential use followed by remote connection",
                description="Credential use and remote movement appear close in time.",
                enabled=self._rule_enabled("R007_CREDENTIAL_TO_REMOTE"),
                severity="high",
                stage_hints=("credential_access", "lateral_movement"),
                temporal_window_seconds=900,
                score=self._weight("R007_CREDENTIAL_TO_REMOTE", 0.7),
                confidence=0.83,
                evidence_ttl_seconds=3600,
                technique_ids=("T1555", "T1021"),
                evaluator=lambda event, ctx: bool(
                    ctx.features["credential_then_lateral_activity_900s"].value
                ),
            ),
            DetectionRule(
                rule_id="R008_DECEPTION_INTERACTION",
                name="Deception interaction",
                description="Honey credential or decoy interaction observed.",
                enabled=self._rule_enabled("R008_DECEPTION_INTERACTION"),
                severity="critical",
                stage_hints=("credential_access", "lateral_movement", "collection"),
                temporal_window_seconds=3600,
                score=self._weight("R008_DECEPTION_INTERACTION", 0.98),
                confidence=0.98,
                evidence_ttl_seconds=86400,
                technique_ids=("T1005", "T1555"),
                evaluator=lambda event, ctx: bool(
                    ctx.features["is_deception_interaction"].value
                    or ctx.features["uses_honey_credential"].value
                    or ctx.features["targets_decoy"].value
                ),
            ),
            DetectionRule(
                rule_id="R009_CRITICAL_ASSET_APPROACH",
                name="Access toward a critical asset",
                description="Suspicious entity touched or approached a critical asset.",
                enabled=self._rule_enabled("R009_CRITICAL_ASSET_APPROACH"),
                severity="high",
                stage_hints=("lateral_movement", "collection"),
                temporal_window_seconds=900,
                score=self._weight("R009_CRITICAL_ASSET_APPROACH", 0.68),
                confidence=0.78,
                evidence_ttl_seconds=3600,
                technique_ids=("T1021", "T1005"),
                evaluator=lambda event, ctx: bool(
                    ctx.features["targets_critical_asset"].value
                    and (ctx.recent_evidence_count > 0 or event.event_type != "asset_discovered")
                ),
            ),
            DetectionRule(
                rule_id="R010_BENIGN_ADMIN_SUPPRESSION",
                name="Benign administrative suppression",
                description="Activity matches approved administrative host or service account.",
                enabled=self._rule_enabled("R010_BENIGN_ADMIN_SUPPRESSION"),
                severity="info",
                stage_hints=("normal",),
                temporal_window_seconds=3600,
                score=-0.45,
                confidence=0.75,
                evidence_ttl_seconds=1800,
                technique_ids=(),
                evaluator=lambda event, ctx: bool(
                    not ctx.features["is_deception_interaction"].value
                    and (
                        self._is_approved_host(event, ctx)
                        or self._is_approved_service(event)
                        or bool(event.attributes.get("maintenance_window"))
                    )
                ),
                suppresses=True,
            ),
        ]

    def _is_approved_host(self, event: SecurityEvent, context: DetectionContext) -> bool:
        hostname = str(
            event.attributes.get("hostname")
            or event.attributes.get("src_hostname")
            or ""
        ).lower()
        return hostname in {host.lower() for host in context.approved_admin_hosts}

    def _is_approved_service(self, event: SecurityEvent) -> bool:
        username = str(event.attributes.get("username") or "").lower()
        configured = {
            account.lower()
            for account in self.config.get("approved_service_accounts", [])
        }
        return username in configured or username.startswith("svc-")
