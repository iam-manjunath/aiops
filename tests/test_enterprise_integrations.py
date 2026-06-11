from aiops_agent.azure_clients import (
    AzureEnterpriseIntegrationClient,
    build_default_alert_signal_query,
    build_resource_discovery_query,
    build_security_findings_query,
    summarize_security_findings,
)
from aiops_agent.azure_openai import AzureOpenAIService, _extract_response_text
from aiops_agent.config import Settings
from aiops_agent.models import (
    AlertPollRequest,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResponse,
    ResourceDiscoveryRequest,
)
from aiops_agent.workflow import is_log_analytics_incident_signal


def test_integration_status_reports_enterprise_modes(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a,sub-b",
        log_analytics_workspace_map="sub-a=workspace-a,sub-b=workspace-b",
    )
    client = AzureEnterpriseIntegrationClient(settings)

    status = client.status()

    assert status.subscriptions_configured == 2
    assert status.log_analytics_configured is True
    assert status.log_analytics_workspace_mappings_configured == 2
    assert "Azure Monitor Action Group webhook" in status.supported_ingestion_modes
    assert "Microsoft.ContainerService/managedClusters" in status.supported_resource_types


def test_log_analytics_query_uses_subscription_workspace_mapping(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_map="sub-a=workspace-a,sub-b=workspace-b",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.query_log_analytics(
        LogAnalyticsQueryRequest(query="AzureActivity | take 1", subscription_id="sub-b")
    )

    assert response.status == "configuration_only"
    assert response.workspace_id == "workspace-b"
    assert response.rows == [{"query": "AzureActivity | take 1"}]


def test_log_analytics_query_explicit_workspace_overrides_mapping(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_map="sub-a=workspace-a",
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.query_log_analytics(
        LogAnalyticsQueryRequest(
            query="AzureActivity | take 1",
            subscription_id="sub-a",
            workspace_id="override-workspace",
        )
    )

    assert response.workspace_id == "override-workspace"


def test_log_analytics_query_rejects_workspace_name(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_id="workspace-name",
        enable_live_azure_integrations=True,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.query_log_analytics(LogAnalyticsQueryRequest(query="AzureActivity | take 1"))

    assert response.status == "invalid_workspace_id"
    assert "customerId GUID" in response.message


def test_workspace_map_accepts_json(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_map='{"sub-a":"workspace-a"}',
    )

    assert settings.resolve_workspace_id("sub-a") == "workspace-a"


def test_resource_discovery_query_includes_vmss_and_aks():
    query = build_resource_discovery_query(
        [
            "microsoft.compute/virtualmachinescalesets",
            "microsoft.containerservice/managedclusters",
        ],
        25,
    )

    assert "microsoft.compute/virtualmachinescalesets" in query
    assert "microsoft.containerservice/managedclusters" in query
    assert "limit 25" in query


def test_poll_alerts_requires_workspace_configuration(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_id=None,
        log_analytics_workspace_map="",
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.poll_workspace_alert_signals(AlertPollRequest())

    assert response.status == "not_configured"


def test_default_alert_signal_query_is_enterprise_kql():
    query = build_default_alert_signal_query(10)

    assert "AzureActivity" in query
    assert "Event" in query
    assert "Perf" in query
    assert "AzureMetrics" in query
    assert "SNATPortUtilization" in query
    assert "VipAvailability" in query
    assert "ObservedValue >= 70" in query
    assert "take 10" in query


def test_log_analytics_incident_signal_requires_alert_shape():
    assert is_log_analytics_incident_signal(
        {
            "TimeGenerated": "2026-05-27T10:00:00Z",
            "Severity": "Sev3",
            "RuleName": "Azure Firewall metric breach: SNATPortUtilization",
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw",
            "Description": "SNATPortUtilization observed value 75 Percent",
        }
    )
    assert not is_log_analytics_incident_signal(
        {
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw",
            "MetricName": "NetworkRuleHit",
            "Samples": 55,
            "TotalValue": 24223,
        }
    )


def test_discover_resources_is_configuration_only_with_subscriptions(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.discover_resources(ResourceDiscoveryRequest(limit=5))

    assert response.status == "configuration_only"
    assert response.subscriptions == ["sub-a"]
    assert "Resources" in response.query


def test_cost_analysis_requires_subscription_configuration(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.get_cost_analysis()

    assert response["status"] == "not_configured"


def test_cost_analysis_returns_configuration_shape_when_live_disabled(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.get_cost_analysis(timeframe="TheLastMonth", top=15)

    assert response["status"] == "configuration_only"
    assert response["subscriptions"] == ["sub-a"]
    assert response["query_shape"]["timeframe"] == "TheLastMonth"
    assert response["query_shape"]["dataset"]["top"] == 15


def test_security_findings_requires_subscription_configuration(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.get_security_findings()

    assert response["status"] == "not_configured"


def test_security_findings_returns_configuration_query_when_live_disabled(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.get_security_findings(limit=40)

    assert response["status"] == "configuration_only"
    assert response["subscriptions"] == ["sub-a"]
    assert "securityresources" in response["query"]
    assert "limit 40" in response["query"]


def test_security_findings_query_targets_unhealthy_assessments():
    query = build_security_findings_query(25)

    assert "microsoft.security/assessments" in query
    assert 'status !in~ ("Healthy", "NotApplicable")' in query
    assert "limit 25" in query


def test_security_findings_summary_counts_severities():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Unspecified"},
        {"severity": None},
    ]

    summary = summarize_security_findings(findings)

    assert summary == {"high": 1, "medium": 1, "low": 1, "unknown": 2}


def test_azure_openai_status_requires_endpoint_deployment_and_auth(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_openai_endpoint=None,
        azure_openai_deployment=None,
        azure_openai_api_key=None,
    )
    service = AzureOpenAIService(settings)

    status = service.status()

    assert status.configured is False
    assert status.endpoint_configured is False
    assert "AIOPS_AZURE_OPENAI_ENDPOINT" in status.message


def test_azure_openai_status_supports_api_key_mode(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_openai_endpoint="https://example.openai.azure.com/",
        azure_openai_deployment="gpt-test",
        azure_openai_api_key="test-key",
        azure_openai_auth_mode="api_key",
    )
    service = AzureOpenAIService(settings)

    status = service.status()

    assert status.configured is True
    assert status.auth_mode == "api_key"
    assert status.api_key_configured is True


def test_azure_openai_smoke_test_returns_not_configured_without_secrets(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_openai_endpoint="https://example.openai.azure.com/",
        azure_openai_deployment="gpt-test",
        azure_openai_api_key=None,
        azure_openai_auth_mode="api_key",
    )
    service = AzureOpenAIService(settings)

    response = service.test_chat("hello")

    assert response.status == "not_configured"


def test_azure_openai_log_analysis_requires_configured_model(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_openai_endpoint=None,
        azure_openai_deployment=None,
        azure_openai_api_key=None,
    )
    service = AzureOpenAIService(settings)
    query_result = LogAnalyticsQueryResponse(
        status="ok",
        workspace_id="workspace-a",
        columns=["TimeGenerated", "ResourceId", "Description"],
        rows=[
            {
                "TimeGenerated": "2026-05-27T10:00:00Z",
                "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
                "Description": "CPU exceeded threshold",
            }
        ],
    )

    response = service.analyze_log_rows(query_result, "Analyze", max_rows=10)

    assert response.query_status == "ok"
    assert response.analysis_status == "not_configured"
    assert response.row_count == 1


def test_azure_openai_extracts_responses_api_output_text():
    response = {"output_text": "AzureMetrics shows CPU pressure."}

    assert _extract_response_text(response) == "AzureMetrics shows CPU pressure."


def test_azure_openai_extracts_nested_chat_content():
    response = {
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": "Analyze vmss-prod."},
                        {"type": "text", "text": "Recommend approval-gated scale out."},
                    ]
                }
            }
        ]
    }

    assert (
        _extract_response_text(response)
        == "Analyze vmss-prod. Recommend approval-gated scale out."
    )


def test_azure_openai_extracts_nested_responses_output():
    response = {
        "output": [
            {
                "type": "message",
                "content": [
                    {
                        "type": "output_text",
                        "text": "No critical anomaly in the returned rows.",
                    }
                ],
            }
        ]
    }

    assert _extract_response_text(response) == "No critical anomaly in the returned rows."
