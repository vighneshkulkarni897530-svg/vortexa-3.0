"""Tests for Benchmark Evaluation Endpoint and Dataset (Laptop 4 / Track C-03)."""

import pytest
from fastapi.testclient import TestClient
from backend.main import app


@pytest.fixture
def backend_client():
    return TestClient(app)


def test_get_benchmark_dataset(backend_client):
    res = backend_client.get("/api/v1/benchmark/dataset")
    assert res.status_code == 200
    data = res.json()
    assert data["total_samples"] >= 40
    assert "samples" in data
    # Verify official Master prompt categories present
    categories = {s["attack_category"] for s in data["samples"]}
    assert "DIRECT_INJECTION" in categories
    assert "INDIRECT_INJECTION" in categories
    assert ("DATA_EXFILTRATION" in categories or "SECRET_LEAK" in categories)
    assert ("LEGITIMATE_CONTENT" in categories or "BENIGN_QUERY" in categories)


def test_run_benchmark_evaluation(backend_client):
    res = backend_client.post("/api/v1/benchmark/run")
    assert res.status_code == 200
    report = res.json()
    assert report["sample_count"] >= 40
    binary_total = (
        report["true_positives"]
        + report["false_positives"]
        + report["true_negatives"]
        + report["false_negatives"]
    )
    ambiguous_count = report["class_balance"].get("AMBIGUOUS", 0)
    assert binary_total + ambiguous_count == report["sample_count"]
    assert report["precision"] >= 0.90
    assert report["recall"] >= 0.90
    assert report["accuracy"] >= 0.90
    assert "category_breakdown" in report
    assert "sample_results" in report
