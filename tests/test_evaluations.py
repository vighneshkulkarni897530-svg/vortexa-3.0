import pytest
from fastapi.testclient import TestClient


def test_record_evaluation_run_deterministic_metrics(client: TestClient, admin_headers: dict):
    payload = {
        "dataset_name": "prompt_injection_benchmark_v3",
        "dataset_version": "3.2.0",
        "sample_count": 100,
        "true_positives": 45,
        "false_positives": 5,
        "true_negatives": 45,
        "false_negatives": 5,
        "execution_status": "COMPLETED",
        "report_metadata": {
            "evaluator": "laptop-4-test-harness",
            "model_tested": "llama-3-8b",
        },
    }

    res = client.post("/api/v1/evaluations", json=payload, headers=admin_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["sample_count"] == 100
    assert data["precision"] == 0.90
    assert data["recall"] == 0.90
    assert data["false_positive_rate"] == 0.10
    assert data["false_negative_rate"] == 0.10
    assert data["execution_status"] == "COMPLETED"

    # Verify retrieval
    get_res = client.get(f"/api/v1/evaluations/{data['id']}", headers=admin_headers)
    assert get_res.status_code == 200
    assert get_res.json()["dataset_name"] == payload["dataset_name"]


def test_reject_fabricated_metrics_matrix_mismatch(client: TestClient, admin_headers: dict):
    """
    Validation prevents submitting fabricated sample counts that do not match the confusion matrix.
    """
    invalid_payload = {
        "dataset_name": "fabricated_dataset",
        "dataset_version": "1.0",
        "sample_count": 200,  # Sum is only 100!
        "true_positives": 45,
        "false_positives": 5,
        "true_negatives": 45,
        "false_negatives": 5,
        "execution_status": "COMPLETED",
    }

    res = client.post("/api/v1/evaluations", json=invalid_payload, headers=admin_headers)
    assert res.status_code == 422
