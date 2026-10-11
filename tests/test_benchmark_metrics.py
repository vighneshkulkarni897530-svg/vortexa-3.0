"""Unit tests for benchmark metrics calculation with zero-denominator handling.

Verifies mathematical accuracy of Precision, Recall, F1 Score, Accuracy,
FPR, Missed-Attack Rate, and Policy Compliance Accuracy across edge cases.
"""

import pytest
from backend.detection.benchmark_runner import calculate_binary_metrics


def test_metrics_perfect_evaluation():
    """Verify metrics calculation on 100% accurate run (40 TP, 12 TN, 0 FP, 0 FN)."""
    m = calculate_binary_metrics(
        true_positives=40,
        false_positives=0,
        true_negatives=12,
        false_negatives=0,
        total_ambiguous=8,
        correct_ambiguous=8,
    )
    assert m.binary_total == 52
    assert m.precision == 1.0
    assert m.precision_display == "100.00%"
    assert m.recall == 1.0
    assert m.recall_display == "100.00%"
    assert m.f1_score == 1.0
    assert m.f1_score_display == "100.00%"
    assert m.accuracy == 1.0
    assert m.accuracy_display == "100.00%"
    assert m.false_positive_rate == 0.0
    assert m.false_positive_rate_display == "0.00%"
    assert m.missed_attack_rate == 0.0
    assert m.missed_attack_rate_display == "0.00%"
    assert m.policy_compliance_accuracy == 1.0
    assert m.policy_compliance_accuracy_display == "100.00%"


def test_metrics_historical_run_resolves_60_vs_52_discrepancy():
    """Verify historical run with 1 false negative (39 TP, 1 FN, 12 TN, 0 FP).

    This mathematically proves the source of 98.1% (binary 51/52) versus
    98.3% (overall policy compliance 59/60).
    """
    m = calculate_binary_metrics(
        true_positives=39,
        false_positives=0,
        true_negatives=12,
        false_negatives=1,
        total_ambiguous=8,
        correct_ambiguous=8,
    )
    assert m.binary_total == 52
    # Binary Accuracy: 51 / 52 = 98.08%
    assert m.accuracy == 0.9808
    assert m.accuracy_display == "98.08%"
    # Policy Compliance Accuracy: 59 / 60 = 98.33%
    assert m.policy_compliance_accuracy == 0.9833
    assert m.policy_compliance_accuracy_display == "98.33%"
    # Precision: 39 / 39 = 100.00%
    assert m.precision == 1.0
    # Recall: 39 / 40 = 97.50%
    assert m.recall == 0.975
    assert m.recall_display == "97.50%"
    # F1 Score: 2 * (1.0 * 0.975) / (1.0 + 0.975) = 1.95 / 1.975 = 0.9873
    assert m.f1_score == 0.9873
    assert m.f1_score_display == "98.73%"
    # Missed-attack rate (FNR): 1 / 40 = 2.50%
    assert m.missed_attack_rate == 0.025
    assert m.missed_attack_rate_display == "2.50%"
    # False-positive rate: 0 / 12 = 0.00%
    assert m.false_positive_rate == 0.0
    assert m.false_positive_rate_display == "0.00%"


def test_metrics_all_zeros_empty_dataset():
    """Verify that an empty dataset safely returns N/A for all metrics without ZeroDivisionError."""
    m = calculate_binary_metrics(
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        total_ambiguous=0,
        correct_ambiguous=0,
    )
    assert m.binary_total == 0
    assert m.precision is None
    assert m.precision_display == "N/A"
    assert m.recall is None
    assert m.recall_display == "N/A"
    assert m.f1_score is None
    assert m.f1_score_display == "N/A"
    assert m.accuracy is None
    assert m.accuracy_display == "N/A"
    assert m.false_positive_rate is None
    assert m.false_positive_rate_display == "N/A"
    assert m.missed_attack_rate is None
    assert m.missed_attack_rate_display == "N/A"
    assert m.policy_compliance_accuracy is None
    assert m.policy_compliance_accuracy_display == "N/A"


def test_metrics_zero_positive_predictions():
    """Verify when detector made zero positive predictions (TP=0, FP=0)."""
    m = calculate_binary_metrics(
        true_positives=0,
        false_positives=0,
        true_negatives=20,
        false_negatives=5,
    )
    assert m.binary_total == 25
    assert m.precision is None
    assert m.precision_display == "N/A"
    assert m.recall == 0.0
    assert m.recall_display == "0.00%"
    assert m.f1_score is None
    assert m.f1_score_display == "N/A"
    assert m.accuracy == 0.8
    assert m.accuracy_display == "80.00%"
    assert m.false_positive_rate == 0.0
    assert m.missed_attack_rate == 1.0


def test_metrics_zero_negative_samples():
    """Verify when evaluation dataset has zero negative samples (FP=0, TN=0)."""
    m = calculate_binary_metrics(
        true_positives=10,
        false_positives=0,
        true_negatives=0,
        false_negatives=2,
    )
    assert m.binary_total == 12
    assert m.precision == 1.0
    assert m.recall == round(10 / 12, 4)
    assert m.false_positive_rate is None
    assert m.false_positive_rate_display == "N/A"
