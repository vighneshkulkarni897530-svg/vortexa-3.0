import pytest
from fastapi.testclient import TestClient
from promptshield.db.models import SecurityPolicy, PolicyVersion, AuditEvent


def test_admin_create_policy_and_version_snapshot(client: TestClient, admin_headers: dict):
    payload = {
        "name": "Strict Agent Gateway Policy",
        "description": "Screens high-risk automated agent tool calls",
        "is_enabled": True,
        "source_applicability": ["TOOL_OUTPUT", "RETRIEVED_DOC"],
        "rule_config": {
            "rules": [
                {"name": "No Secrets", "category": "SECRET_LEAK", "action": "BLOCK"}
            ]
        },
        "severity_thresholds": {
            "CRITICAL": "BLOCK",
            "HIGH": "BLOCK",
            "MEDIUM": "ESCALATE",
            "LOW": "ALLOW"
        },
        "default_action": "ALLOW",
        "change_summary": "Initial gateway release v1",
    }

    res = client.post("/api/v1/policies", json=payload, headers=admin_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == payload["name"]
    assert data["current_version"] == 1

    # Verify version 1 snapshot was created
    versions_res = client.get(f"/api/v1/policies/{data['id']}/versions", headers=admin_headers)
    assert versions_res.status_code == 200
    versions = versions_res.json()
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["configuration_snapshot"]["name"] == payload["name"]
    assert versions[0]["change_summary"] == "Initial gateway release v1"


def test_unauthorized_policy_creation(client: TestClient, user_headers: dict):
    payload = {
        "name": "Malicious Attacker Policy",
        "default_action": "ALLOW",
        "change_summary": "Attacker attempt",
    }

    # 1. Ordinary user -> 403 Forbidden
    res_user = client.post("/api/v1/policies", json=payload, headers=user_headers)
    assert res_user.status_code == 403

    # 2. Anonymous request -> 401 Unauthorized
    res_anon = client.post("/api/v1/policies", json=payload)
    assert res_anon.status_code == 401


def test_policy_update_creates_new_version(client: TestClient, admin_headers: dict, default_policy: SecurityPolicy):
    update_payload = {
        "description": "Updated policy with stricter data exfiltration thresholds",
        "default_action": "BLOCK",
        "change_summary": "Tighten default action from ALLOW to BLOCK after incident INC-402",
    }

    res = client.put(f"/api/v1/policies/{default_policy.id}", json=update_payload, headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["current_version"] == 2
    assert data["default_action"] == "BLOCK"

    # Verify version history has both versions
    ver_res = client.get(f"/api/v1/policies/{default_policy.id}/versions", headers=admin_headers)
    assert ver_res.status_code == 200
    versions = ver_res.json()
    assert len(versions) == 2
    assert versions[0]["version_number"] == 2
    assert versions[0]["configuration_snapshot"]["default_action"] == "BLOCK"
    assert versions[1]["version_number"] == 1
    assert versions[1]["configuration_snapshot"]["default_action"] == "ALLOW"


def test_list_and_filter_policies(client: TestClient, user_headers: dict, default_policy: SecurityPolicy):
    res = client.get("/api/v1/policies?source_type=USER_PROMPT", headers=user_headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    assert items[0]["id"] == default_policy.id


def test_policy_duplicate_name_conflict(client: TestClient, admin_headers: dict, default_policy: SecurityPolicy):
    payload = {
        "name": default_policy.name,  # Duplicate name
        "default_action": "ALLOW",
        "change_summary": "Duplicate attempt",
    }
    res = client.post("/api/v1/policies", json=payload, headers=admin_headers)
    assert res.status_code == 409
