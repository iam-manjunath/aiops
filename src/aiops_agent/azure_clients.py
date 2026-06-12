from datetime import timedelta
from uuid import UUID
from typing import Any

import httpx

from aiops_agent.config import Settings
from aiops_agent.models import (
    ActionType,
    AlertPollRequest,
    AzureSubscription,
    AzureSubscriptionListResponse,
    IntegrationStatus,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResponse,
    NormalizedAlert,
    RemediationAction,
    ResourceDiscoveryRequest,
    ResourceDiscoveryResponse,
)


class AzureContextCollector:
    """Collects Azure context when configuration is available.

    The MVP returns structured placeholders for missing configuration so incident
    analysis remains useful during local development and tests.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def collect(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "resource_inventory": self._resource_inventory(alert),
            "recent_logs": self._recent_logs(alert),
            "advisor_recommendations": self._advisor_recommendations(alert),
            "security_context": self._security_context(alert),
            "monitoring_recommendations": self._monitoring_recommendations(alert),
        }

    def _resource_inventory(self, alert: NormalizedAlert) -> dict[str, Any]:
        resources = []
        for resource_id in alert.resource_ids:
            parsed = parse_resource_id(resource_id)
            resources.append(
                {
                    "id": resource_id,
                    "subscription_id": parsed.get("subscriptions"),
                    "resource_group": parsed.get("resourceGroups"),
                    "provider": parsed.get("providers"),
                    "resource_type": parsed.get("type_path"),
                    "name": parsed.get("name"),
                }
            )
        return {
            "status": "configured" if self.settings.subscription_id_list else "not_configured",
            "resources": resources,
        }

    def _recent_logs(self, alert: NormalizedAlert) -> dict[str, Any]:
        subscription_id = None
        if alert.primary_resource_id:
            subscription_id = parse_resource_id(alert.primary_resource_id).get("subscriptions")
        workspace_id = self.settings.resolve_workspace_id(subscription_id)

        if not workspace_id:
            return {
                "status": "not_configured",
                "subscription_id": subscription_id,
                "queries": [
                    "Perf | where CounterName in ('% Processor Time', 'Available MBytes')",
                    "Event | where EventLevelName in ('Error', 'Warning')",
                    "AzureActivity | where ActivityStatusValue != 'Success'",
                ],
            }
        return {
            "status": "configured",
            "subscription_id": subscription_id,
            "workspace_id": workspace_id,
            "queries": build_resource_context_queries(alert),
            "note": (
                "Use /integrations/log-analytics/query or /integrations/log-analytics/poll-alerts "
                "with subscription_id to execute KQL against the mapped workspace."
            ),
        }

    def _advisor_recommendations(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "status": "extension_point",
            "categories": ["HighAvailability", "Security", "Performance", "Cost"],
            "resource_ids": alert.resource_ids,
        }

    def _security_context(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "status": "extension_point",
            "sentinel_ueba_relevant": alert.is_security_alert,
            "signals": ["Sentinel incidents", "Defender alerts", "UEBA entity anomalies"],
        }

    def _monitoring_recommendations(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "dynamic_thresholds": [
                "Use Azure Monitor dynamic thresholds for recurring noisy CPU, memory, disk, and availability signals."
            ],
            "predictive_scaling": [
                "Use VMSS predictive autoscale for cyclical CPU-bound workloads with enough history."
            ],
        }


class AzureRemediationClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def execute_live(self, action: RemediationAction) -> str:
        if action.type == ActionType.RUN_AUTOMATION_WEBHOOK:
            return self._run_automation_webhook(action)
        if action.type == ActionType.RESTART_VM:
            return self._restart_vm(action)
        if action.type == ActionType.RESIZE_VMSS:
            return self._resize_vmss(action)
        if action.type == ActionType.ADJUST_AUTOSCALE_RULE:
            return "Autoscale adjustment is prepared; apply the generated rule through Azure Monitor change control."
        if action.type == ActionType.CREATE_TICKET:
            return "Ticket connector is not configured; recorded ticket creation request."
        if action.type == ActionType.MANUAL_ACTION_REQUIRED:
            return "Manual action recorded; no Azure mutation executed."
        raise ValueError(f"Unsupported action type: {action.type}")

    def _run_automation_webhook(self, action: RemediationAction) -> str:
        webhook_url = action.metadata.get("webhook_url") or self.settings.automation_webhook_url
        if not webhook_url:
            raise ValueError("Automation webhook URL is not configured.")
        response = httpx.post(webhook_url, json=action.metadata.get("payload", {}), timeout=30)
        response.raise_for_status()
        return f"Automation webhook accepted with HTTP {response.status_code}."

    def _restart_vm(self, action: RemediationAction) -> str:
        target = action.affected_resources[0] if action.affected_resources else None
        if not target:
            raise ValueError("restart_vm action requires an affected VM resource id.")
        parsed = parse_resource_id(target)
        return (
            "Live VM restart adapter reached. Configure azure-mgmt-compute call for "
            f"{parsed.get('resourceGroups')}/{parsed.get('name')} after RBAC validation."
        )

    def _resize_vmss(self, action: RemediationAction) -> str:
        target = action.affected_resources[0] if action.affected_resources else None
        if not target:
            raise ValueError("resize_vmss action requires an affected VMSS resource id.")
        desired_capacity = action.metadata.get("desired_capacity", "current+1")
        return f"Live VMSS resize adapter reached for {target}; desired capacity {desired_capacity}."


class AzureEnterpriseIntegrationClient:
    """Read-side Azure integrations for existing enterprise infrastructure."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def status(self) -> IntegrationStatus:
        return IntegrationStatus(
            mode="live" if self.settings.enable_live_azure_integrations else "configuration_only",
            live_azure_integrations_enabled=self.settings.enable_live_azure_integrations,
            subscriptions_configured=len(self.settings.subscription_id_list),
            log_analytics_configured=bool(
                self.settings.log_analytics_workspace_id or self.settings.workspace_map
            ),
            log_analytics_workspace_mappings_configured=len(self.settings.workspace_map),
            azure_openai_configured=self.settings.azure_openai_enabled,
            supported_ingestion_modes=[
                "Azure Monitor Action Group webhook",
                "Log Analytics KQL polling",
                "Resource Graph inventory discovery",
                "Sentinel/Defender alert extension",
            ],
            supported_resource_types=[
                "Microsoft.Compute/virtualMachines",
                "Microsoft.Compute/virtualMachineScaleSets",
                "Microsoft.ContainerService/managedClusters",
            ],
        )

    def list_accessible_subscriptions(
        self,
        access_token: str | None = None,
    ) -> AzureSubscriptionListResponse:
        configured = self.settings.subscription_id_list
        if configured:
            return AzureSubscriptionListResponse(
                status="ok",
                source="configuration",
                subscriptions=[
                    AzureSubscription(subscription_id=subscription_id)
                    for subscription_id in configured
                ],
                message="Using configured subscription list from AIOPS_AZURE_SUBSCRIPTION_IDS.",
            )

        if not self.settings.enable_live_azure_integrations:
            return AzureSubscriptionListResponse(
                status="not_configured",
                source="none",
                subscriptions=[],
                message=(
                    "No configured subscriptions found. Set AIOPS_AZURE_SUBSCRIPTION_IDS or "
                    "enable AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to auto-discover."
                ),
            )

        try:
            discovered = self._list_accessible_subscriptions(access_token=access_token)
        except Exception as exc:
            return AzureSubscriptionListResponse(
                status="error",
                source="live_azure",
                subscriptions=[],
                message=f"Failed to discover subscriptions: {exc}",
            )

        if not discovered:
            return AzureSubscriptionListResponse(
                status="ok",
                source="live_azure",
                subscriptions=[],
                message="No accessible subscriptions were returned for the current Azure identity.",
            )

        return AzureSubscriptionListResponse(
            status="ok",
            source="live_azure",
            subscriptions=discovered,
        )

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
        access_token: str | None = None,
        logs_access_token: str | None = None,
    ) -> LogAnalyticsQueryResponse:
        workspace_id = request.workspace_id or self.settings.resolve_workspace_id(request.subscription_id)
        if not workspace_id and self.settings.enable_live_azure_integrations:
            if request.subscription_id:
                workspace_id = self._discover_workspace_customer_id(
                    request.subscription_id,
                    access_token=access_token,
                )
            else:
                subscriptions, _ = self._resolve_subscriptions(None, access_token=access_token)
                if len(subscriptions) == 1:
                    workspace_id = self._discover_workspace_customer_id(
                        subscriptions[0],
                        access_token=access_token,
                    )
        if not workspace_id:
            message = "Set AIOPS_LOG_ANALYTICS_WORKSPACE_ID, pass workspace_id, or configure "
            message += (
                "AIOPS_LOG_ANALYTICS_WORKSPACE_MAP and pass subscription_id. "
                "With live integrations enabled, workspace can be auto-discovered for a subscription."
            )
            return LogAnalyticsQueryResponse(
                status="not_configured",
                workspace_id=None,
                message=message,
            )
        if not self.settings.enable_live_azure_integrations:
            return LogAnalyticsQueryResponse(
                status="configuration_only",
                workspace_id=workspace_id,
                columns=["query"],
                rows=[{"query": request.query}],
                message="Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to execute live KQL.",
            )
        if not is_guid(workspace_id):
            return LogAnalyticsQueryResponse(
                status="invalid_workspace_id",
                workspace_id=workspace_id,
                message=(
                    "Log Analytics queries require the workspace customerId GUID, not the "
                    "workspace resource name. In Azure Portal this is shown as Workspace ID."
                ),
            )

        try:
            if logs_access_token:
                return self._query_log_analytics_with_delegated_token(
                    workspace_id=workspace_id,
                    query=request.query,
                    timespan_minutes=request.timespan_minutes or self.settings.log_query_timespan_minutes,
                    logs_access_token=logs_access_token,
                )

            from azure.identity import DefaultAzureCredential
            from azure.monitor.query import LogsQueryClient, LogsQueryStatus

            client = LogsQueryClient(DefaultAzureCredential())
            response = client.query_workspace(
                workspace_id=workspace_id,
                query=request.query,
                timespan=timedelta(
                    minutes=request.timespan_minutes or self.settings.log_query_timespan_minutes
                ),
            )

            if response.status == LogsQueryStatus.PARTIAL:
                table = response.partial_data[0] if response.partial_data else None
                message = str(response.partial_error)
            else:
                table = response.tables[0] if response.tables else None
                message = None

            if not table:
                return LogAnalyticsQueryResponse(
                    status="ok",
                    workspace_id=workspace_id,
                    message=message or "Query returned no tables.",
                )

            columns = [column.name if hasattr(column, "name") else str(column) for column in table.columns]
            rows = [dict(zip(columns, row, strict=False)) for row in table.rows]
            return LogAnalyticsQueryResponse(
                status="partial" if response.status == LogsQueryStatus.PARTIAL else "ok",
                workspace_id=workspace_id,
                columns=columns,
                rows=rows,
                message=message,
            )
        except Exception as exc:
            return LogAnalyticsQueryResponse(
                status="error",
                workspace_id=workspace_id,
                message=f"Azure Monitor query integration failed: {exc}",
            )

    def poll_workspace_alert_signals(
        self,
        request: AlertPollRequest,
        access_token: str | None = None,
        logs_access_token: str | None = None,
    ) -> LogAnalyticsQueryResponse:
        query = request.query or build_default_alert_signal_query(request.max_alerts)
        return self.query_log_analytics(
            LogAnalyticsQueryRequest(
                query=query,
                subscription_id=request.subscription_id,
                workspace_id=request.workspace_id,
                timespan_minutes=request.timespan_minutes,
            ),
            access_token=access_token,
            logs_access_token=logs_access_token,
        )

    def discover_resources(
        self,
        request: ResourceDiscoveryRequest,
        access_token: str | None = None,
    ) -> ResourceDiscoveryResponse:
        subscriptions, subscription_message = self._resolve_subscriptions(
            request.subscriptions,
            access_token=access_token,
        )
        query = build_resource_discovery_query(request.resource_types, request.limit)
        if not subscriptions:
            return ResourceDiscoveryResponse(
                status="not_configured",
                subscriptions=[],
                query=query,
                message=subscription_message or "Set AIOPS_AZURE_SUBSCRIPTION_IDS or pass subscriptions.",
            )
        if not self.settings.enable_live_azure_integrations:
            return ResourceDiscoveryResponse(
                status="configuration_only",
                subscriptions=subscriptions,
                query=query,
                message="Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to query Resource Graph.",
            )

        try:
            response = self._query_resource_graph(subscriptions, query, access_token=access_token)
            return ResourceDiscoveryResponse(
                status="ok",
                subscriptions=subscriptions,
                query=query,
                resources=response,
            )
        except Exception as exc:
            return ResourceDiscoveryResponse(
                status="error",
                subscriptions=subscriptions,
                query=query,
                message=f"Resource Graph integration failed: {exc}",
            )

    def get_cost_analysis(
        self,
        subscriptions: list[str] | None = None,
        timeframe: str = "MonthToDate",
        top: int = 10,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        resolved_subscriptions, subscription_message = self._resolve_subscriptions(
            subscriptions,
            access_token=access_token,
        )
        if not resolved_subscriptions:
            return {
                "status": "not_configured",
                "subscriptions": [],
                "message": subscription_message or "Set AIOPS_AZURE_SUBSCRIPTION_IDS or pass subscriptions.",
            }
        if not self.settings.enable_live_azure_integrations:
            return {
                "status": "configuration_only",
                "subscriptions": resolved_subscriptions,
                "timeframe": timeframe,
                "top": top,
                "message": "Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to query Cost Management.",
                "query_shape": {
                    "type": "ActualCost",
                    "timeframe": timeframe,
                    "dataset": {
                        "granularity": "None",
                        "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                        "grouping": [
                            {"type": "Dimension", "name": "ResourceId"},
                            {"type": "Dimension", "name": "ServiceName"},
                        ],
                        "top": top,
                    },
                },
            }

        results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for subscription_id in resolved_subscriptions:
            try:
                if access_token:
                    query_response = self._query_cost_for_subscription(
                        subscription_id,
                        timeframe,
                        top,
                        access_token=access_token,
                    )
                else:
                    query_response = self._query_cost_for_subscription(subscription_id, timeframe, top)
                columns = [
                    str(column.get("name"))
                    for column in query_response.get("properties", {}).get("columns", [])
                ]
                rows = query_response.get("properties", {}).get("rows", [])
                results.append(
                    {
                        "subscription_id": subscription_id,
                        "columns": columns,
                        "rows": [dict(zip(columns, row, strict=False)) for row in rows],
                    }
                )
            except Exception as exc:
                errors.append({"subscription_id": subscription_id, "message": str(exc)})

        status = "ok"
        if errors and results:
            status = "partial"
        if errors and not results:
            status = "error"

        return {
            "status": status,
            "timeframe": timeframe,
            "subscriptions": resolved_subscriptions,
            "subscription_results": results,
            "errors": errors,
        }

    def get_security_findings(
        self,
        subscriptions: list[str] | None = None,
        limit: int = 100,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        resolved_subscriptions, subscription_message = self._resolve_subscriptions(
            subscriptions,
            access_token=access_token,
        )
        if not resolved_subscriptions:
            return {
                "status": "not_configured",
                "subscriptions": [],
                "message": subscription_message or "Set AIOPS_AZURE_SUBSCRIPTION_IDS or pass subscriptions.",
            }

        query = build_security_findings_query(limit)
        if not self.settings.enable_live_azure_integrations:
            return {
                "status": "configuration_only",
                "subscriptions": resolved_subscriptions,
                "query": query,
                "message": "Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to query security findings.",
            }

        try:
            resources = self._query_resource_graph(
                resolved_subscriptions,
                query,
                access_token=access_token,
            )
            return {
                "status": "ok",
                "subscriptions": resolved_subscriptions,
                "query": query,
                "findings": resources,
                "finding_count": len(resources),
                "severity_summary": summarize_security_findings(resources),
            }
        except Exception as exc:
            return {
                "status": "error",
                "subscriptions": resolved_subscriptions,
                "query": query,
                "message": f"Security findings integration failed: {exc}",
            }

    def _query_cost_for_subscription(
        self,
        subscription_id: str,
        timeframe: str,
        top: int,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        token = access_token or self._management_access_token()
        url = (
            "https://management.azure.com/subscriptions/"
            f"{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        )
        payload = {
            "type": "ActualCost",
            "timeframe": timeframe,
            "dataset": {
                "granularity": "None",
                "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                "grouping": [
                    {"type": "Dimension", "name": "ResourceId"},
                    {"type": "Dimension", "name": "ServiceName"},
                ],
                "top": top,
            },
        }
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
            timeout=45,
        )
        response.raise_for_status()
        return response.json()

    def _resolve_subscriptions(
        self,
        requested: list[str] | None,
        access_token: str | None = None,
    ) -> tuple[list[str], str | None]:
        if requested:
            return requested, None
        if self.settings.subscription_id_list:
            return self.settings.subscription_id_list, None
        if not self.settings.enable_live_azure_integrations:
            return (
                [],
                "Set AIOPS_AZURE_SUBSCRIPTION_IDS or pass subscriptions.",
            )

        try:
            discovered = self._list_accessible_subscriptions(access_token=access_token)
        except Exception as exc:
            return [], f"Subscription auto-discovery failed: {exc}"

        subscription_ids = [item.subscription_id for item in discovered if item.subscription_id]
        if not subscription_ids:
            return [], "No accessible subscriptions were returned for the current Azure identity."
        return subscription_ids, None

    def _management_access_token(self) -> str:
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential().get_token("https://management.azure.com/.default").token

    def _list_accessible_subscriptions(
        self,
        access_token: str | None = None,
    ) -> list[AzureSubscription]:
        token = access_token or self._management_access_token()
        response = httpx.get(
            "https://management.azure.com/subscriptions?api-version=2022-12-01",
            headers={"Authorization": f"Bearer {token}"},
            timeout=45,
        )
        response.raise_for_status()
        payload = response.json()
        subscriptions = []
        for item in payload.get("value", []):
            subscriptions.append(
                AzureSubscription(
                    subscription_id=str(item.get("subscriptionId") or "").strip(),
                    display_name=item.get("displayName"),
                    state=item.get("state"),
                    tenant_id=item.get("tenantId"),
                )
            )
        return [item for item in subscriptions if item.subscription_id]

    def _discover_workspace_customer_id(
        self,
        subscription_id: str,
        access_token: str | None = None,
    ) -> str | None:
        token = access_token or self._management_access_token()
        response = httpx.get(
            "https://management.azure.com/subscriptions/"
            f"{subscription_id}/providers/Microsoft.OperationalInsights/workspaces"
            "?api-version=2023-09-01",
            headers={"Authorization": f"Bearer {token}"},
            timeout=45,
        )
        response.raise_for_status()
        payload = response.json()
        workspaces = payload.get("value", [])
        if not workspaces:
            return None
        sorted_workspaces = sorted(
            workspaces,
            key=lambda item: str(item.get("name") or "").lower(),
        )
        customer_id = sorted_workspaces[0].get("properties", {}).get("customerId")
        return str(customer_id).strip() if customer_id else None

    def _query_resource_graph(
        self,
        subscriptions: list[str],
        query: str,
        access_token: str | None = None,
    ) -> list[dict[str, Any]]:
        if access_token:
            url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01"
            payload = {"subscriptions": subscriptions, "query": query}
            response = httpx.post(
                url,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json=payload,
                timeout=45,
            )
            response.raise_for_status()
            return list(response.json().get("data") or [])

        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        client = ResourceGraphClient(DefaultAzureCredential())
        response = client.resources(QueryRequest(subscriptions=subscriptions, query=query))
        return list(response.data or [])

    def _query_log_analytics_with_delegated_token(
        self,
        workspace_id: str,
        query: str,
        timespan_minutes: int,
        logs_access_token: str,
    ) -> LogAnalyticsQueryResponse:
        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        payload = {"query": query, "timespan": f"PT{max(timespan_minutes, 1)}M"}
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {logs_access_token}", "Content-Type": "application/json"},
            json=payload,
            timeout=45,
        )
        if response.status_code >= 400:
            return LogAnalyticsQueryResponse(
                status="error",
                workspace_id=workspace_id,
                message=f"Azure Monitor query integration failed: {response.text}",
            )
        body = response.json()
        tables = body.get("tables") or []
        if not tables:
            return LogAnalyticsQueryResponse(
                status="ok",
                workspace_id=workspace_id,
                message="Query returned no tables.",
            )

        table = tables[0]
        columns = [str(column.get("name")) for column in table.get("columns", [])]
        rows = [dict(zip(columns, row, strict=False)) for row in table.get("rows", [])]
        return LogAnalyticsQueryResponse(
            status="ok",
            workspace_id=workspace_id,
            columns=columns,
            rows=rows,
        )


def build_resource_context_queries(alert: NormalizedAlert) -> list[str]:
    quoted_resources = ",".join(f"'{resource_id}'" for resource_id in alert.resource_ids)
    resource_filter = f"| where _ResourceId in~ ({quoted_resources})" if alert.resource_ids else ""
    return [
        (
            "Perf "
            f"{resource_filter} "
            "| where TimeGenerated > ago(1h) "
            "| summarize avg(CounterValue), max(CounterValue) "
            "by Computer, CounterName, bin(TimeGenerated, 5m)"
        ),
        (
            "AzureActivity "
            f"{resource_filter} "
            "| where TimeGenerated > ago(1h) "
            "| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, _ResourceId"
        ),
        (
            "InsightsMetrics "
            f"{resource_filter} "
            "| where TimeGenerated > ago(1h) "
            "| summarize avg(Val), max(Val) by Namespace, Name, bin(TimeGenerated, 5m)"
        ),
    ]


def build_default_alert_signal_query(max_alerts: int) -> str:
    return f"""
let window = ago(1h);
union isfuzzy=true
(
    AzureActivity
    | where TimeGenerated >= window
    | where ActivityStatusValue in~ ("Failed", "Failure")
    | project TimeGenerated, Severity="Sev3",
        RuleName=strcat("AzureActivity failure: ", OperationNameValue),
        ResourceId=_ResourceId,
        Description=tostring(Properties)
),
(
    Event
    | where TimeGenerated >= window
    | where EventLevelName in ("Error", "Warning")
    | project TimeGenerated,
        Severity=iif(EventLevelName == "Error", "Sev2", "Sev3"),
        RuleName=strcat("Windows event: ", Source),
        ResourceId=_ResourceId,
        Description=RenderedDescription
),
(
    Perf
    | where TimeGenerated >= window
    | where CounterName == "% Processor Time" and CounterValue > 90
    | summarize CounterValue=max(CounterValue) by bin(TimeGenerated, 5m), _ResourceId
    | project TimeGenerated, Severity="Sev2",
        RuleName="High CPU from Log Analytics",
        ResourceId=_ResourceId,
        Description=strcat("CPU above threshold: ", tostring(CounterValue))
),
(
    AzureMetrics
    | where TimeGenerated >= window
    | where MetricName in~ ("Percentage CPU", "CpuPercentage", "CPU Credits Remaining",
        "Available Memory Bytes", "UsedCapacity", "FirewallHealth", "SNATPortUtilization",
        "VipAvailability")
    | summarize
        Average=max(Average),
        Maximum=max(Maximum),
        Total=max(Total)
        by bin(TimeGenerated, 5m), ResourceId, MetricName, UnitName
    | extend ObservedValue=coalesce(Maximum, Average, Total)
    | where isnotempty(ResourceId) and isnotempty(ObservedValue)
    | where
        (MetricName in~ ("Percentage CPU", "CpuPercentage") and ObservedValue >= 90)
        or (MetricName =~ "CPU Credits Remaining" and ObservedValue <= 10)
        or (MetricName =~ "Available Memory Bytes" and ObservedValue <= 1073741824)
        or (MetricName =~ "UsedCapacity" and ObservedValue >= 80)
        or (MetricName =~ "FirewallHealth" and ObservedValue < 100)
        or (MetricName =~ "SNATPortUtilization" and ObservedValue >= 70)
        or (MetricName =~ "VipAvailability" and ObservedValue < 99.9)
    | project TimeGenerated,
        Severity=case(
            MetricName in~ ("Percentage CPU", "CpuPercentage") and ObservedValue >= 90, "Sev2",
            MetricName =~ "CPU Credits Remaining" and ObservedValue <= 10, "Sev2",
            MetricName =~ "Available Memory Bytes" and ObservedValue <= 1073741824, "Sev3",
            MetricName =~ "FirewallHealth" and ObservedValue < 100, "Sev2",
            MetricName =~ "SNATPortUtilization" and ObservedValue >= 85, "Sev2",
            MetricName =~ "VipAvailability" and ObservedValue < 99.9, "Sev2",
            "Sev3"
        ),
        RuleName=strcat("AzureMetrics anomaly: ", MetricName),
        ResourceId,
        Description=strcat(MetricName, " observed value ", tostring(ObservedValue), " ", tostring(UnitName))
)
| where isnotempty(ResourceId)
| order by TimeGenerated desc
| take {max_alerts}
""".strip()


def build_resource_discovery_query(resource_types: list[str], limit: int) -> str:
    type_list = ",".join(f"'{resource_type.lower()}'" for resource_type in resource_types)
    return f"""
Resources
| where type in~ ({type_list})
| project id, name, type, location, resourceGroup, subscriptionId, tags, sku, properties
| order by type asc, name asc
| limit {limit}
""".strip()


def build_security_findings_query(limit: int) -> str:
    return f"""
securityresources
| where type =~ "microsoft.security/assessments"
| extend assessmentKey=name
| extend status=tostring(properties.status.code)
| extend severity=tostring(properties.metadata.severity)
| extend displayName=tostring(properties.displayName)
| extend resourceId=tostring(properties.resourceDetails.id)
| where status !in~ ("Healthy", "NotApplicable")
| project subscriptionId, resourceId, assessmentKey, displayName, severity, status
| order by severity desc, displayName asc
| limit {limit}
""".strip()


def summarize_security_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity in summary:
            summary[severity] += 1
        else:
            summary["unknown"] += 1
    return summary


def is_guid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False


def parse_resource_id(resource_id: str) -> dict[str, str]:
    parts = [part for part in resource_id.strip("/").split("/") if part]
    parsed: dict[str, str] = {}
    for index, part in enumerate(parts):
        if part in {"subscriptions", "resourceGroups", "providers"} and index + 1 < len(parts):
            parsed[part] = parts[index + 1]

    if "providers" in parsed:
        provider_index = parts.index("providers")
        provider_parts = parts[provider_index + 2 :]
        if len(provider_parts) >= 2:
            parsed["type_path"] = "/".join(provider_parts[0::2])
            parsed["name"] = provider_parts[-1]
    return parsed
