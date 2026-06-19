"""Shadow Mode controller for recommendations and analyst feedback."""

from __future__ import annotations

from datetime import timedelta

from mirage.domain.schemas import (
    AnalystDecision,
    AnalystFeedback,
    AttackAnalysisResult,
    SafetyDecision,
    SafetyVerdict,
    ShadowMetrics,
    ShadowRecommendation,
    ShadowStatus,
)
from mirage.execution.utils import action_tier, deterministic_id, ensure_utc


class ShadowModeController:
    """Generate recommendations without invoking enforcement adapters."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.recommendation_ttl_seconds = int(
            self.config.get("recommendation_ttl_seconds", 3600)
        )
        self.recommendations: dict[str, ShadowRecommendation] = {}
        self.feedback: dict[str, AnalystFeedback] = {}

    def evaluate_analysis(
        self,
        analysis_result: AttackAnalysisResult,
        safety_decisions: list[SafetyDecision],
        reference_time,
    ) -> list[ShadowRecommendation]:
        """Create shadow recommendations from analysis and safety decisions."""
        reference = ensure_utc(reference_time)
        decisions = {decision.action_id: decision for decision in safety_decisions}
        generated: list[ShadowRecommendation] = []
        for action in analysis_result.candidate_action_set.actions:
            decision = decisions.get(action.action_id)
            if decision is None:
                continue
            tier = action_tier(action.action_type, self.config)
            would_execute = decision.verdict in {
                SafetyVerdict.ALLOW,
                SafetyVerdict.ALLOW_WITH_MONITORING,
            }
            recommendation_id = deterministic_id(
                "shadow-rec",
                analysis_result.analysis_id,
                action.action_id,
                decision.verdict.value,
                analysis_result.twin_version,
                analysis_result.belief_version,
            )
            rec = ShadowRecommendation(
                recommendation_id=recommendation_id,
                source_analysis_id=analysis_result.analysis_id,
                action_id=action.action_id,
                safety_verdict=decision.verdict,
                shadow_status=ShadowStatus.GENERATED,
                recommendation_timestamp=reference,
                expiry=reference + timedelta(seconds=self.recommendation_ttl_seconds),
                proposed_execution_tier=tier,
                would_execute=would_execute,
                would_execute_reason=(
                    "Would execute in lab/shadow policy."
                    if would_execute
                    else "; ".join(decision.violated_policies or decision.required_approvals or decision.reasons)
                ),
                predicted_benefit=action.expected_risk_reduction,
                predicted_business_risk=action.business_risk,
                evidence_ids=action.supporting_evidence_ids,
                twin_version=str(analysis_result.twin_version),
                graph_version=str(analysis_result.graph_version),
                belief_version=str(analysis_result.belief_version),
                analysis_version=analysis_result.analysis_id,
                policy_version=decision.policy_version,
                explanation=(
                    f"Recommend {action.action_type} for {', '.join(action.target_entity_ids)}. "
                    f"Reason: {action.reason}"
                ),
                uncertainty=action.uncertainty,
            )
            self.recommendations[recommendation_id] = rec
            generated.append(rec)
        return generated

    def record_feedback(
        self,
        feedback: AnalystFeedback,
    ) -> None:
        """Store analyst feedback and update recommendation lifecycle."""
        self.feedback[feedback.feedback_id] = feedback
        rec = self.recommendations.get(feedback.recommendation_id)
        if rec is None:
            return
        status = {
            AnalystDecision.ACCEPT: ShadowStatus.ACCEPTED,
            AnalystDecision.REJECT: ShadowStatus.REJECTED,
            AnalystDecision.DEFER: ShadowStatus.DEFERRED,
            AnalystDecision.DUPLICATE: ShadowStatus.REJECTED,
            AnalystDecision.INSUFFICIENT_EVIDENCE: ShadowStatus.DEFERRED,
            AnalystDecision.UNSAFE: ShadowStatus.REJECTED,
            AnalystDecision.IRRELEVANT: ShadowStatus.REJECTED,
        }[feedback.analyst_decision]
        self.recommendations[feedback.recommendation_id] = rec.model_copy(
            update={"shadow_status": status}
        )

    def get_recommendations(
        self,
        status: str | None = None,
        *,
        reference_time=None,
    ) -> list[ShadowRecommendation]:
        """Return recommendations, expiring old entries first."""
        reference = ensure_utc(reference_time)
        for rec_id, rec in list(self.recommendations.items()):
            if rec.expiry <= reference and rec.shadow_status not in {
                ShadowStatus.ACCEPTED,
                ShadowStatus.REJECTED,
            }:
                self.recommendations[rec_id] = rec.model_copy(
                    update={"shadow_status": ShadowStatus.EXPIRED}
                )
        values = list(self.recommendations.values())
        if status:
            values = [rec for rec in values if rec.shadow_status.value == status]
        return sorted(values, key=lambda rec: (rec.recommendation_timestamp, rec.recommendation_id))

    def metrics(self) -> ShadowMetrics:
        """Return simple shadow evaluation metrics."""
        recs = list(self.recommendations.values())
        total = len(recs)
        feedback = list(self.feedback.values())
        accepted = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.ACCEPT)
        rejected = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.REJECT)
        deferred = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.DEFER)
        duplicate = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.DUPLICATE)
        insufficient = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.INSUFFICIENT_EVIDENCE)
        unsafe = sum(1 for item in feedback if item.analyst_decision == AnalystDecision.UNSAFE)
        blocked = sum(1 for rec in recs if rec.safety_verdict == SafetyVerdict.DENY)
        approval = sum(1 for rec in recs if rec.safety_verdict == SafetyVerdict.REQUIRE_APPROVAL)
        with_evidence = sum(1 for rec in recs if rec.evidence_ids or rec.explanation)
        with_explanation = sum(1 for rec in recs if rec.explanation)
        avg_coverage = sum(float(rec.twin_version != "") for rec in recs) / total if total else 0.0
        return ShadowMetrics(
            recommendation_count=total,
            acceptance_rate=accepted / len(feedback) if feedback else 0.0,
            rejection_rate=rejected / len(feedback) if feedback else 0.0,
            defer_rate=deferred / len(feedback) if feedback else 0.0,
            duplicate_recommendation_rate=duplicate / len(feedback) if feedback else 0.0,
            insufficient_evidence_rate=insufficient / len(feedback) if feedback else 0.0,
            unsafe_recommendation_rate=unsafe / len(feedback) if feedback else 0.0,
            complete_evidence_pct=with_evidence / total if total else 0.0,
            complete_explanation_pct=with_explanation / total if total else 0.0,
            blocked_by_safety_pct=blocked / total if total else 0.0,
            approval_required_pct=approval / total if total else 0.0,
            twin_coverage_at_recommendation=avg_coverage,
            twin_freshness_at_recommendation=avg_coverage,
            generated_at=ensure_utc(None),
        )
