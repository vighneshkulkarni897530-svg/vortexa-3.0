"""Risk Assessment and Calibrated Scoring (Stage E).

Calculates a documented, explainable risk score (0.00 to 1.00), aggregates
findings, and derives an actionable risk classification and recommendation.

NOTE ON INTERPRETATION:
The risk score is a deterministic weighted threat severity index based on
detector confidence and compounded signal severity. It is NOT a statistical
probability of attack.
"""

from typing import List, Tuple
from backend.detection.schemas import (
    DecisionAction,
    DetectionFinding,
    RiskClassification,
    Severity,
    SourceType,
)
from backend.detection.source_context import SourceContext


# Base severity weight weights for scoring
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.15,
}


class RiskAssessmentEngine:
    """Computes deterministic threat scores and classifications from findings."""

    @staticmethod
    def assess(
        findings: List[DetectionFinding],
        source_ctx: SourceContext,
    ) -> Tuple[float, RiskClassification, DecisionAction]:
        """Calculates risk score, classification, and recommended action."""
        if not findings:
            return 0.0, RiskClassification.SAFE, DecisionAction.ALLOW

        # Filter out purely benign informatory findings (severity LOW with action ALLOW)
        actionable_findings = [f for f in findings if f.recommended_action != DecisionAction.ALLOW]

        if not actionable_findings:
            # Only informatory or benign educational findings exist
            return 0.10, RiskClassification.SAFE, DecisionAction.ALLOW

        # Calculate base threat from highest-severity actionable finding
        max_threat = 0.0
        compounding_threat = 0.0

        for f in actionable_findings:
            base_w = SEVERITY_WEIGHTS.get(f.severity, 0.2)
            finding_score = base_w * f.confidence
            if finding_score > max_threat:
                max_threat = finding_score
            compounding_threat += finding_score * 0.05  # Slight boost for multi-vector attacks

        # Composite score clamped strictly between 0.00 and 1.00
        composite_score = min(1.0, round(max_threat + compounding_threat, 4))

        # Determine Classification
        if composite_score >= 0.90:
            classification = RiskClassification.CRITICAL
        elif composite_score >= 0.70:
            classification = RiskClassification.HIGH
        elif composite_score >= 0.45:
            classification = RiskClassification.MEDIUM
        elif composite_score >= 0.20:
            classification = RiskClassification.LOW
        else:
            classification = RiskClassification.SAFE

        # Determine Recommended Action based on severity and source context
        has_critical = any(f.severity == Severity.CRITICAL for f in actionable_findings)
        has_high = any(f.severity == Severity.HIGH for f in actionable_findings)
        has_medium = any(f.severity == Severity.MEDIUM for f in actionable_findings)

        if has_critical:
            recommended_action = DecisionAction.BLOCK
        elif has_high:
            if source_ctx.source_type == SourceType.USER_PROMPT:
                recommended_action = DecisionAction.BLOCK
            else:
                # Untrusted document / webpage: check if spans are safely sanitizable
                can_sanitize = all(
                    f.evidence_span is not None for f in actionable_findings
                )
                recommended_action = DecisionAction.SANITIZE if can_sanitize else DecisionAction.BLOCK
        elif has_medium:
            if any(f.recommended_action == DecisionAction.ESCALATE for f in actionable_findings):
                recommended_action = DecisionAction.ESCALATE
            elif any(f.evidence_span is not None for f in actionable_findings):
                recommended_action = DecisionAction.SANITIZE
            else:
                recommended_action = DecisionAction.ESCALATE
        else:
            recommended_action = DecisionAction.ALLOW

        return composite_score, classification, recommended_action
