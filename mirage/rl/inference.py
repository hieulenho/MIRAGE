"""Read-only offline RL inference service."""

from __future__ import annotations

import time

from mirage.domain.schemas import ActionMask, CandidateDefenseAction, SafetyDecision, SafetyVerdict
from mirage.rl.baselines import HeuristicCandidatePolicy
from mirage.rl.features import ActionFeatureEncoder, simple_safety_decision_for_action
from mirage.rl.policy import OfflineBlueTeamPolicy
from mirage.rl.schema import EncodedRLState, PolicyHealth, PolicyInferenceResult, RLOperatingMode


class OfflineRLInferenceService:
    """Read-only inference service.  It never trains or calls enforcement."""

    def __init__(
        self,
        *,
        operating_mode: str = RLOperatingMode.RL_SHADOW.value,
        max_candidate_actions: int = 100,
        uncertainty_threshold: float = 0.65,
    ) -> None:
        self.operating_mode = operating_mode
        self.max_candidate_actions = int(max_candidate_actions)
        self.uncertainty_threshold = float(uncertainty_threshold)
        self.policy: OfflineBlueTeamPolicy | None = None
        self._total = 0
        self._fallbacks = 0
        self._ood = 0
        self._last_latency_ms = 0.0
        self._warnings: list[str] = []

    def load_policy(self, path: str) -> None:
        self.policy = OfflineBlueTeamPolicy.load(path)

    def recommend(
        self,
        encoded_state: EncodedRLState,
        candidate_actions: list[CandidateDefenseAction] | None = None,
        action_masks: dict[str, ActionMask] | None = None,
        safety_context: dict[str, SafetyDecision] | None = None,
    ) -> PolicyInferenceResult:
        start = time.perf_counter()
        if len(encoded_state.candidate_action_features) > self.max_candidate_actions:
            raise ValueError(
                f"candidate action count exceeds limit {self.max_candidate_actions}"
            )
        if candidate_actions is not None and action_masks is not None:
            encoded_state = self._reencode_actions(encoded_state, candidate_actions, action_masks, safety_context or {})
        warnings = list(encoded_state.warnings)
        if self.policy is None:
            result = HeuristicCandidatePolicy().recommend(encoded_state)
            result = result.model_copy(
                update={
                    "policy_id": "offline_rl_unloaded",
                    "fallback_used": True,
                    "fallback_reason": "no_policy_loaded",
                    "ood_warnings": warnings,
                    "explanation": "No offline RL policy loaded; heuristic fallback used.",
                }
            )
        else:
            result = self.policy.recommend(encoded_state)
            if result.policy_uncertainty >= self.uncertainty_threshold:
                fallback = HeuristicCandidatePolicy().recommend(encoded_state)
                result = fallback.model_copy(
                    update={
                        "policy_id": self.policy.policy_id,
                        "policy_version": self.policy.policy_version,
                        "fallback_used": True,
                        "fallback_reason": "uncertainty_threshold_exceeded",
                        "ood_warnings": [*warnings, "high_policy_uncertainty"],
                        "explanation": "Offline RL uncertainty exceeded threshold; heuristic fallback used.",
                    }
                )
        selected_decision = None
        if safety_context and result.selected_action_id in safety_context:
            selected_decision = safety_context[result.selected_action_id]
            if selected_decision.verdict == SafetyVerdict.DENY:
                fallback = HeuristicCandidatePolicy().recommend(encoded_state)
                result = fallback.model_copy(
                    update={
                        "policy_id": result.policy_id,
                        "policy_version": result.policy_version,
                        "fallback_used": True,
                        "fallback_reason": "safety_gate_denied_selected_action",
                        "safety_gate_result": selected_decision,
                        "explanation": "Safety Gate denied RL-selected action; fallback recommendation returned.",
                    }
                )
        elif result.selected_action_id != "__NO_OP__":
            selected_feature = next(
                (feature for feature in encoded_state.candidate_action_features if feature.action_id == result.selected_action_id),
                None,
            )
            if selected_feature is not None:
                dummy_action = _feature_to_action(selected_feature)
                selected_decision = simple_safety_decision_for_action(dummy_action, None)
        latency = (time.perf_counter() - start) * 1000.0
        self._last_latency_ms = latency
        self._total += 1
        self._fallbacks += int(result.fallback_used)
        self._ood += len(result.ood_warnings)
        return result.model_copy(
            update={
                "safety_gate_result": selected_decision,
                "inference_time_ms": round(latency, 3),
                "action_mask_applied": True,
            }
        )

    def health(self) -> PolicyHealth:
        status = "ok" if self.policy is not None else "no_policy"
        return PolicyHealth(
            status=status,
            policy_id=self.policy.policy_id if self.policy else "",
            policy_version=self.policy.policy_version if self.policy else "",
            operating_mode=self.operating_mode,
            feature_schema_version="rl_state_v1",
            action_schema_version="rl_action_v1",
            total_inferences=self._total,
            fallback_count=self._fallbacks,
            ood_warning_count=self._ood,
            last_inference_time_ms=round(self._last_latency_ms, 3),
            warnings=list(self._warnings),
        )

    def _reencode_actions(
        self,
        state: EncodedRLState,
        actions: list[CandidateDefenseAction],
        masks: dict[str, ActionMask],
        safety: dict[str, SafetyDecision],
    ) -> EncodedRLState:
        encoder = ActionFeatureEncoder(schema=state.feature_schema)
        features = [
            encoder.encode(
                action,
                masks.get(action.action_id),
                safety.get(action.action_id),
                total_paths=max(1, max((len(a.affected_path_ids) for a in actions), default=1)),
            )
            for action in actions
        ]
        return state.model_copy(
            update={
                "candidate_action_features": features,
                "allowed_action_ids": [
                    action.action_id for action in actions
                    if masks.get(action.action_id) is None or masks[action.action_id].allowed
                ],
                "masked_action_ids": [
                    action_id for action_id, mask in masks.items() if not mask.allowed
                ],
            }
        )


def _feature_to_action(feature):
    from datetime import datetime, timezone
    from mirage.domain.schemas import AutomationLevel, CandidateDefenseAction

    return CandidateDefenseAction(
        action_id=feature.action_id,
        action_type=feature.action_type,
        target_entity_ids=[],
        affected_path_ids=[],
        affected_edge_ids=[],
        expected_risk_reduction=feature.expected_risk_reduction,
        expected_information_gain=feature.information_gain,
        operational_cost=feature.operational_cost,
        business_risk=feature.business_risk,
        deployment_cost=feature.deployment_cost,
        confidence=feature.confidence,
        uncertainty=feature.uncertainty,
        risk_tier=feature.risk_tier,
        automation_level=AutomationLevel.RECOMMEND_ONLY.value,
        requires_approval=feature.approval_required,
        rollback_supported=feature.reversibility > 0,
        ttl_seconds=feature.ttl_seconds,
        reason="reconstructed from RL action feature for safety context",
        generated_at=datetime.now(timezone.utc),
    )
