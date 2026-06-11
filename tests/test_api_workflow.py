from fastapi.testclient import TestClient

from aiops_agent.app import create_app
from aiops_agent.config import Settings


def test_root_renders_html_service_status(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Service Status" in response.text
    assert "Azure AIOps Agent" in response.text


def test_api_status_documents_python_runtime_and_enterprise_endpoints(client):
    response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["runtime"]["language"] == "python"
    assert body["runtime"]["framework"] == "fastapi"
    assert body["auth"]["enabled"] is False
    assert body["docs"] == "/docs"
    assert body["endpoints"]["log_analytics_query"] == "POST /integrations/log-analytics/query"
    assert body["endpoints"]["log_analytics_analyze"] == "POST /integrations/log-analytics/analyze"
    assert body["endpoints"]["azure_openai_status"] == "GET /integrations/azure-openai/status"
    assert body["endpoints"]["resource_graph_discovery"] == (
        "POST /integrations/resource-graph/discover"
    )


def test_azure_openai_status_endpoint_reports_not_configured(client):
    response = client.get("/integrations/azure-openai/status")

    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["endpoint_configured"] is False


def test_me_returns_html_profile_when_auth_is_disabled(client):
    response = client.get("/me")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Local operator" in response.text


def test_api_me_returns_json_profile_when_auth_is_disabled(client):
    response = client.get("/api/me")

    assert response.status_code == 200
    assert response.json()["username"] == "local"


def test_operator_routes_require_login_when_auth_is_enabled(tmp_path):
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            auth_enabled=True,
            auth_client_id="client-id",
            auth_client_secret="client-secret",
            auth_session_secret="test-session-secret",
        )
    )
    with TestClient(app) as auth_client:
        response = auth_client.get("/incidents")

    assert response.status_code == 401
    assert "Microsoft login required" in response.json()["detail"]


def test_auth_status_reports_microsoft_authority_when_enabled(tmp_path):
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            auth_enabled=True,
            auth_tenant_id="contoso-tenant-id",
            auth_client_id="client-id",
            auth_client_secret="client-secret",
            auth_session_secret="test-session-secret",
        )
    )
    with TestClient(app) as auth_client:
        response = auth_client.get("/auth/status")

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["configured"] is True
    assert body["authority"] == "https://login.microsoftonline.com/contoso-tenant-id"


def test_ingest_and_approve_vmss_alert(client, sample_alert):
    ingest_response = client.post("/alerts/azure-monitor", json=sample_alert)
    assert ingest_response.status_code == 200
    body = ingest_response.json()
    assert body["status"] == "open"
    assert len(body["action_ids"]) == 1

    incident_id = body["incident_id"]
    incident = client.get(f"/incidents/{incident_id}").json()
    assert "VMSS capacity pressure" in incident["summary"]

    actions = client.get(f"/incidents/{incident_id}/actions").json()
    assert actions[0]["type"] == "resize_vmss"
    assert actions[0]["status"] == "proposed"

    approve = client.post(
        f"/incidents/{incident_id}/approve",
        json={"approver": "operator@example.com", "comment": "Approved in test"},
    )
    assert approve.status_code == 200
    result = approve.json()[0]
    assert result["status"] == "succeeded"
    assert "Mock execution completed" in result["output"]

    action = client.get(f"/actions/{body['action_ids'][0]}").json()
    assert action["approved_by"] == "operator@example.com"
    assert action["status"] == "succeeded"


def test_reject_incident_rejects_proposed_actions(client, sample_alert):
    incident_id = client.post("/alerts/azure-monitor", json=sample_alert).json()["incident_id"]

    response = client.post(
        f"/incidents/{incident_id}/reject",
        json={"rejected_by": "lead@example.com", "reason": "Duplicate incident"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    actions = client.get(f"/incidents/{incident_id}/actions").json()
    assert actions[0]["status"] == "rejected"


def test_api_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "Azure AIOps Agent"
    assert "timestamp_utc" in body


def test_api_tools_execute_search_resources(client):
    response = client.post(
        "/api/tools/execute",
        json={
            "tool": "search_resources",
            "arguments": {
                "subscriptions": ["sub-a"],
                "resource_types": ["microsoft.compute/virtualmachines"],
                "limit": 5,
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["tool"] == "search_resources"
    assert body["result"]["status"] == "configuration_only"


def test_api_chat_routes_to_activity_logs_tool(client):
    response = client.post(
        "/api/chat",
        json={"message": "What changed in the last 24 hours?"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["suggested_tool"] == "get_activity_logs"
    assert body["tool_result"]["status"] in {"not_configured", "configuration_only", "ok", "partial"}
