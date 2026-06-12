import html
import re
import sys
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from aiops_agent.ai_search import AzureAISearchService
from aiops_agent.analyzer import build_analyzer
from aiops_agent.auth import (
    SESSION_TOKEN_REF_KEY,
    SESSION_USER_KEY,
    auth_status,
    build_user_profile,
    configure_auth,
    get_obo_access_token,
    microsoft_logout_url,
    require_user,
    session_user,
    store_session_token,
)
from aiops_agent.azure_openai import AzureOpenAIService
from aiops_agent.azure_clients import (
    AzureContextCollector,
    AzureEnterpriseIntegrationClient,
    AzureRemediationClient,
)
from aiops_agent.config import Settings, get_settings
from aiops_agent.models import (
    AlertPollRequest,
    AlertIngestResponse,
    ApproveRequest,
    AuthStatus,
    AuditEvent,
    AzureSubscriptionListResponse,
    AzureAISearchStatus,
    AzureOpenAIStatus,
    AzureOpenAITestRequest,
    AzureOpenAITestResponse,
    ChatRequest,
    ChatResponse,
    Incident,
    IntegrationStatus,
    LogAnalyticsAnalyzeRequest,
    LogAnalyticsAnalyzeResponse,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResponse,
    ModuleDescriptor,
    ModuleRunRequest,
    ModuleRunResponse,
    KnowledgeIngestRequest,
    KnowledgeIngestResponse,
    KnowledgeQueryRequest,
    KnowledgeQueryResponse,
    RejectRequest,
    RemediationAction,
    ResourceDiscoveryRequest,
    ResourceDiscoveryResponse,
    ToolExecutionRequest,
    ToolExecutionResponse,
    UserProfile,
)
from aiops_agent.remediation import RemediationExecutor
from aiops_agent.state import create_state_store
from aiops_agent.workflow import AlertProcessor, is_log_analytics_incident_signal


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = create_state_store(settings)
    context_collector = AzureContextCollector(settings)
    analyzer = build_analyzer(settings)
    processor = AlertProcessor(store, context_collector, analyzer)
    executor = RemediationExecutor(settings, store, AzureRemediationClient(settings))
    integrations = AzureEnterpriseIntegrationClient(settings)
    azure_openai = AzureOpenAIService(settings)
    ai_search = AzureAISearchService(settings, azure_openai)

    app = FastAPI(title=settings.app_name, version="0.1.0")
    oauth = configure_auth(app, settings)
    app.state.settings = settings
    app.state.store = store
    app.state.processor = processor
    app.state.executor = executor
    app.state.integrations = integrations
    app.state.azure_openai = azure_openai
    app.state.ai_search = ai_search
    app.state.session_token_cache = {}
    app.state.obo_token_cache = {}

    def current_user(request: Request) -> UserProfile:
        return require_user(request, settings)

    def service_status() -> dict[str, Any]:
        return {
            "name": settings.app_name,
            "environment": settings.environment,
            "runtime": {
                "language": "python",
                "python_version": sys.version.split()[0],
                "framework": "fastapi",
            },
            "execution_mode": settings.execution_mode,
            "auth": auth_status(settings).model_dump(mode="json"),
            "azure_integrations": integrations.status().model_dump(mode="json"),
            "azure_openai": azure_openai.status().model_dump(mode="json"),
            "ai_search": ai_search.status().model_dump(mode="json"),
            "docs": "/docs",
            "openapi": "/openapi.json",
            "ui": "/ui",
            "endpoints": {
                "health": "GET /healthz",
                "api_health": "GET /api/health",
                "chat": "POST /api/chat",
                "tool_execute": "POST /api/tools/execute",
                "modules": "GET /api/modules",
                "module_run": "POST /api/modules/{module_id}/run",
                "azure_monitor_webhook": "POST /alerts/azure-monitor",
                "integration_status": "GET /integrations/status",
                "azure_subscriptions": "GET /integrations/azure/subscriptions",
                "log_analytics_query": "POST /integrations/log-analytics/query",
                "log_analytics_analyze": "POST /integrations/log-analytics/analyze",
                "log_analytics_poll_alerts": "POST /integrations/log-analytics/poll-alerts",
                "resource_graph_discovery": "POST /integrations/resource-graph/discover",
                "azure_openai_status": "GET /integrations/azure-openai/status",
                "azure_openai_test": "POST /integrations/azure-openai/test",
                "ai_search_status": "GET /integrations/ai-search/status",
                "knowledge_ingest": "POST /integrations/knowledge/ingest",
                "knowledge_query": "POST /integrations/knowledge/query",
                "incidents": "GET /incidents",
                "approval": "POST /incidents/{incident_id}/approve",
                "rejection": "POST /incidents/{incident_id}/reject",
                "profile": "GET /me",
                "profile_json": "GET /api/me",
            },
        }

    supported_tools = [
        "search_resources",
        "get_vm_health",
        "query_monitor_metrics",
        "get_activity_logs",
        "check_nsg_rules",
        "investigate_incident",
        "get_cost_analysis",
        "get_security_findings",
        "ingest_knowledge_base",
        "query_knowledge_base",
        "restart_vm",
        "start_vm",
        "stop_vm",
        "create_snapshot",
        "run_automation_runbook",
    ]

    module_descriptors: list[ModuleDescriptor] = [
        ModuleDescriptor(
            id="resource_discovery_agent",
            title="Resource Discovery Agent",
            purpose="Discover Azure resources across subscriptions and resource groups.",
            primary_tools=["search_resources"],
            status="ready",
        ),
        ModuleDescriptor(
            id="vm_health_agent",
            title="VM Health Agent",
            purpose="Analyze VM runtime health using Azure Monitor and Log Analytics.",
            primary_tools=["get_vm_health", "query_monitor_metrics"],
            status="ready",
        ),
        ModuleDescriptor(
            id="network_troubleshooting_agent",
            title="Network Troubleshooting Agent",
            purpose="Inspect NSG and network-related signals for connectivity triage.",
            primary_tools=["check_nsg_rules", "query_monitor_metrics"],
            status="partial",
        ),
        ModuleDescriptor(
            id="cost_optimization_agent",
            title="Cost Optimization Agent",
            purpose="Identify cost spikes and optimization opportunities using Azure cost data.",
            primary_tools=["get_cost_analysis"],
            status="ready",
        ),
        ModuleDescriptor(
            id="security_agent",
            title="Security Agent",
            purpose="Surface security findings and risky exposure patterns.",
            primary_tools=["get_security_findings"],
            status="ready",
        ),
        ModuleDescriptor(
            id="change_investigation_agent",
            title="Change Investigation Agent",
            purpose="Correlate recent control-plane and deployment changes.",
            primary_tools=["get_activity_logs"],
            status="ready",
        ),
        ModuleDescriptor(
            id="incident_rca_agent",
            title="Incident RCA Agent",
            purpose="Investigate incidents with correlated telemetry and AI-assisted RCA.",
            primary_tools=["investigate_incident"],
            status="ready",
        ),
        ModuleDescriptor(
            id="knowledge_base_agent",
            title="Knowledge Base Agent",
            purpose="Use runbooks/SOPs and enterprise docs via Azure AI Search + RAG.",
            primary_tools=["query_knowledge_base", "ingest_knowledge_base"],
            status="ready",
        ),
        ModuleDescriptor(
            id="automation_agent",
            title="Automation Agent",
            purpose="Run approval-gated operational actions with audit and guardrails.",
            primary_tools=[
                "restart_vm",
                "start_vm",
                "stop_vm",
                "create_snapshot",
                "run_automation_runbook",
            ],
            status="partial",
        ),
    ]

    module_action_map: dict[str, dict[str, str]] = {
        "resource_discovery_agent": {"discover_resources": "search_resources"},
        "vm_health_agent": {
            "analyze_vm_health": "get_vm_health",
            "query_monitor_metrics": "query_monitor_metrics",
        },
        "network_troubleshooting_agent": {
            "check_nsg_rules": "check_nsg_rules",
            "query_monitor_metrics": "query_monitor_metrics",
        },
        "cost_optimization_agent": {"analyze_cost": "get_cost_analysis"},
        "security_agent": {"get_security_findings": "get_security_findings"},
        "change_investigation_agent": {"get_recent_changes": "get_activity_logs"},
        "incident_rca_agent": {"investigate_incident": "investigate_incident"},
        "knowledge_base_agent": {
            "query_knowledge": "query_knowledge_base",
            "ingest_knowledge": "ingest_knowledge_base",
        },
        "automation_agent": {
            "restart_vm": "restart_vm",
            "start_vm": "start_vm",
            "stop_vm": "stop_vm",
            "create_snapshot": "create_snapshot",
            "run_automation_runbook": "run_automation_runbook",
        },
    }

    module_default_action: dict[str, str] = {
        "resource_discovery_agent": "discover_resources",
        "vm_health_agent": "analyze_vm_health",
        "network_troubleshooting_agent": "check_nsg_rules",
        "cost_optimization_agent": "analyze_cost",
        "security_agent": "get_security_findings",
        "change_investigation_agent": "get_recent_changes",
        "incident_rca_agent": "investigate_incident",
        "knowledge_base_agent": "query_knowledge",
        "automation_agent": "restart_vm",
    }

    def parse_string_list(value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return None

    def parse_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def kql_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def resolve_delegated_tokens(
        request: Request,
        *,
        include_logs: bool = False,
    ) -> tuple[str | None, str | None]:
        if not (settings.auth_enabled and settings.auth_enable_obo):
            return None, None

        try:
            management_token = get_obo_access_token(request, settings, settings.auth_obo_arm_scope)
        except Exception as exc:
            if settings.auth_strict_obo:
                raise HTTPException(
                    status_code=502,
                    detail=f"Failed to acquire delegated ARM token: {exc}",
                ) from exc
            management_token = None

        logs_token = None
        if include_logs:
            try:
                logs_token = get_obo_access_token(
                    request,
                    settings,
                    settings.auth_obo_log_analytics_scope,
                )
            except Exception as exc:
                if settings.auth_strict_obo:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Failed to acquire delegated Log Analytics token: {exc}",
                    ) from exc

        if settings.auth_strict_obo:
            if not management_token:
                raise HTTPException(
                    status_code=403,
                    detail="Strict delegated mode is enabled but ARM delegated token is unavailable.",
                )
            if include_logs and not logs_token:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Strict delegated mode is enabled but Log Analytics delegated token "
                        "is unavailable."
                    ),
                )

        return management_token, logs_token

    def execute_tool_call(
        tool_name: str,
        arguments: dict[str, Any],
        *,
        management_token: str | None = None,
        logs_token: str | None = None,
    ) -> tuple[str, dict[str, Any], str | None]:
        if tool_name == "search_resources":
            request = ResourceDiscoveryRequest(
                subscriptions=parse_string_list(arguments.get("subscriptions")),
                resource_types=parse_string_list(arguments.get("resource_types"))
                or ResourceDiscoveryRequest().resource_types,
                limit=parse_int(arguments.get("limit"), 100),
            )
            response = integrations.discover_resources(request, access_token=management_token)
            return "ok", response.model_dump(mode="json"), None

        if tool_name == "query_monitor_metrics":
            query = arguments.get("query") or "AzureMetrics | where TimeGenerated > ago(1h) | take 50"
            request = LogAnalyticsQueryRequest(
                query=query,
                subscription_id=arguments.get("subscription_id"),
                workspace_id=arguments.get("workspace_id"),
                timespan_minutes=parse_int(arguments.get("timespan_minutes"), 60),
            )
            response = integrations.query_log_analytics(
                request,
                access_token=management_token,
                logs_access_token=logs_token,
            )
            return "ok", response.model_dump(mode="json"), None

        if tool_name == "get_activity_logs":
            hours = parse_int(arguments.get("hours"), 24)
            limit = parse_int(arguments.get("limit"), 50)
            query = arguments.get("query") or (
                f"AzureActivity | where TimeGenerated > ago({hours}h) "
                "| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, "
                "_ResourceId, CorrelationId "
                f"| order by TimeGenerated desc | take {limit}"
            )
            request = LogAnalyticsQueryRequest(
                query=query,
                subscription_id=arguments.get("subscription_id"),
                workspace_id=arguments.get("workspace_id"),
                timespan_minutes=parse_int(arguments.get("timespan_minutes"), hours * 60),
            )
            response = integrations.query_log_analytics(
                request,
                access_token=management_token,
                logs_access_token=logs_token,
            )
            return "ok", response.model_dump(mode="json"), None

        if tool_name == "get_vm_health":
            vm_name = str(arguments.get("vm_name") or "").strip()
            resource_id = str(arguments.get("resource_id") or "").strip()
            limit = parse_int(arguments.get("limit"), 50)
            query = arguments.get("query")
            if not query:
                if resource_id:
                    scope_filter = f'| where _ResourceId =~ "{kql_escape(resource_id)}"'
                elif vm_name:
                    scope_filter = f'| where Computer has "{kql_escape(vm_name)}"'
                else:
                    scope_filter = ""
                query = (
                    "let window=ago(1h);"
                    " union isfuzzy=true "
                    "("
                    "Heartbeat "
                    "| where TimeGenerated > window "
                    f"{scope_filter} "
                    "| project TimeGenerated, Computer, _ResourceId, SourceSystem, Category='Heartbeat'"
                    "),"
                    "("
                    "Perf "
                    "| where TimeGenerated > window "
                    "| where CounterName in ('% Processor Time', 'Available MBytes') "
                    f"{scope_filter} "
                    "| project TimeGenerated, Computer, _ResourceId, CounterName, CounterValue, Category='Perf'"
                    ") "
                    "| order by TimeGenerated desc "
                    f"| take {limit}"
                )
            request = LogAnalyticsQueryRequest(
                query=query,
                subscription_id=arguments.get("subscription_id"),
                workspace_id=arguments.get("workspace_id"),
                timespan_minutes=parse_int(arguments.get("timespan_minutes"), 60),
            )
            response = integrations.query_log_analytics(
                request,
                access_token=management_token,
                logs_access_token=logs_token,
            )
            return "ok", response.model_dump(mode="json"), None

        if tool_name == "check_nsg_rules":
            request = ResourceDiscoveryRequest(
                subscriptions=parse_string_list(arguments.get("subscriptions")),
                resource_types=["microsoft.network/networksecuritygroups"],
                limit=parse_int(arguments.get("limit"), 100),
            )
            response = integrations.discover_resources(request, access_token=management_token)
            payload = response.model_dump(mode="json")
            nsg_name = str(arguments.get("nsg_name") or "").strip().lower()
            if nsg_name and payload.get("resources"):
                payload["resources"] = [
                    resource
                    for resource in payload["resources"]
                    if nsg_name in str(resource.get("name", "")).lower()
                ]
            payload["filtered_count"] = len(payload.get("resources", []))
            return "ok", payload, None

        if tool_name == "investigate_incident":
            query = arguments.get("query") or (
                "union isfuzzy=true "
                "(AzureActivity | where TimeGenerated > ago(4h) | where ActivityStatusValue !~ 'Success' "
                "| project TimeGenerated, Severity='Sev3', RuleName=OperationNameValue, "
                "ResourceId=_ResourceId, Description=tostring(Properties)), "
                "(Perf | where TimeGenerated > ago(4h) | where CounterName == '% Processor Time' "
                "| where CounterValue > 90 | project TimeGenerated, Severity='Sev2', "
                "RuleName='High CPU', ResourceId=_ResourceId, "
                "Description=strcat('CPU high: ', tostring(CounterValue))) "
                "| order by TimeGenerated desc | take 50"
            )
            query_request = LogAnalyticsQueryRequest(
                query=query,
                subscription_id=arguments.get("subscription_id"),
                workspace_id=arguments.get("workspace_id"),
                timespan_minutes=parse_int(arguments.get("timespan_minutes"), 240),
            )
            query_response = integrations.query_log_analytics(
                query_request,
                access_token=management_token,
                logs_access_token=logs_token,
            )
            analysis_prompt = arguments.get("prompt") or (
                "Investigate this incident dataset, summarize impact, likely root causes, and "
                "approval-gated corrective actions."
            )
            analysis_response = azure_openai.analyze_log_rows(
                query_result=query_response,
                prompt=analysis_prompt,
                max_rows=parse_int(arguments.get("max_rows"), 50),
            )
            return (
                "ok",
                {
                    "query": query_response.model_dump(mode="json"),
                    "analysis": analysis_response.model_dump(mode="json"),
                },
                None,
            )

        if tool_name in {"restart_vm", "start_vm", "stop_vm", "create_snapshot", "run_automation_runbook"}:
            return (
                "not_implemented",
                {
                    "requested_tool": tool_name,
                    "next_step": "Use incident approval workflow endpoints for controlled execution.",
                    "available_action_types": [
                        "restart_vm",
                        "resize_vmss",
                        "run_automation_webhook",
                        "adjust_autoscale_rule",
                        "create_ticket",
                        "manual_action_required",
                    ],
                },
                "Execution tools are approval-gated and partially scaffolded in this MVP.",
            )

        if tool_name == "get_cost_analysis":
            response = integrations.get_cost_analysis(
                subscriptions=parse_string_list(arguments.get("subscriptions")),
                timeframe=str(arguments.get("timeframe") or "MonthToDate"),
                top=parse_int(arguments.get("top"), 10),
                access_token=management_token,
            )
            status = "ok" if response.get("status") in {"ok", "partial", "configuration_only"} else "error"
            return status, response, response.get("message")

        if tool_name == "get_security_findings":
            response = integrations.get_security_findings(
                subscriptions=parse_string_list(arguments.get("subscriptions")),
                limit=parse_int(arguments.get("limit"), 100),
                access_token=management_token,
            )
            status = "ok" if response.get("status") in {"ok", "configuration_only"} else "error"
            return status, response, response.get("message")

        if tool_name == "ingest_knowledge_base":
            response = ai_search.ingest_local_knowledge(
                source_paths=parse_string_list(arguments.get("source_paths")),
                max_files=parse_int(arguments.get("max_files"), 200),
                force_reindex=bool(arguments.get("force_reindex", False)),
            )
            status = (
                "ok"
                if response.status in {"ok", "partial", "configuration_only", "no_documents"}
                else "error"
            )
            return status, response.model_dump(mode="json"), response.message

        if tool_name == "query_knowledge_base":
            query = str(arguments.get("query") or "").strip()
            if not query:
                return "error", {}, "query_knowledge_base requires a non-empty query argument."
            response = ai_search.query_knowledge(
                query=query,
                top=parse_int(arguments.get("top"), 5),
                use_ai_summary=bool(arguments.get("use_ai_summary", True)),
            )
            status = "ok" if response.status in {"ok", "configuration_only"} else "error"
            return status, response.model_dump(mode="json"), response.message

        return (
            "invalid_tool",
            {},
            f"Unsupported tool '{tool_name}'. Use one of: {', '.join(supported_tools)}",
        )

    def infer_tool_from_message(message: str) -> str | None:
        text = message.lower()
        if any(token in text for token in ["what changed", "changed", "modified", "deployment"]):
            return "get_activity_logs"
        if any(token in text for token in ["cost", "expensive", "idle vm", "rightsizing"]):
            return "get_cost_analysis"
        if any(token in text for token in ["security", "vulnerability", "rdp", "public ip"]):
            return "get_security_findings"
        if any(token in text for token in ["runbook", "sop", "how do i", "recovery", "recover"]):
            return "query_knowledge_base"
        if any(token in text for token in ["ssh", "https", "network", "nsg", "connectivity"]):
            return "check_nsg_rules"
        if any(token in text for token in ["investigate", "rca", "outage", "incident"]):
            return "investigate_incident"
        if any(token in text for token in ["unavailable", "down", "cpu spike", "vm health"]):
            return "get_vm_health"
        if any(token in text for token in ["show", "list", "resources", "vms", "vmss", "aks"]):
            return "search_resources"
        return None

    def infer_arguments_from_message(message: str, tool_name: str) -> dict[str, Any]:
        text = message.lower()
        arguments: dict[str, Any] = {}
        if "last 24" in text or "yesterday" in text:
            arguments["hours"] = 24
        if "last 12" in text:
            arguments["hours"] = 12
        if "last 1 hour" in text or "last hour" in text:
            arguments["hours"] = 1

        quoted = re.search(r"`([^`]+)`", message) or re.search(r"'([^']+)'", message)
        if quoted and tool_name in {"get_vm_health", "restart_vm", "start_vm", "stop_vm"}:
            arguments["vm_name"] = quoted.group(1).strip()

        if tool_name == "search_resources":
            if "vmss" in text:
                arguments["resource_types"] = ["microsoft.compute/virtualmachinescalesets"]
            elif "aks" in text:
                arguments["resource_types"] = ["microsoft.containerservice/managedclusters"]
            elif "vm" in text:
                arguments["resource_types"] = ["microsoft.compute/virtualmachines"]
            arguments["limit"] = 50
        if tool_name == "query_knowledge_base":
            arguments["query"] = message
            arguments["top"] = 5
        return arguments

    @app.get("/", response_class=HTMLResponse, response_model=None)
    def root() -> str:
        return _status_ui(service_status())

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        return service_status()

    @app.get("/auth/status", response_model=AuthStatus)
    def get_auth_status() -> AuthStatus:
        return auth_status(settings)

    @app.get("/auth/login")
    async def auth_login(request: Request):
        if not settings.auth_enabled:
            return RedirectResponse(url="/")
        if not settings.auth_configured:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Microsoft login is enabled but AIOPS_AUTH_CLIENT_ID and "
                    "AIOPS_AUTH_CLIENT_SECRET are not configured."
                ),
            )
        redirect_uri = request.url_for("auth_callback")
        return await oauth.microsoft.authorize_redirect(request, redirect_uri)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        if not settings.auth_configured:
            raise HTTPException(status_code=500, detail="Microsoft login is not configured.")
        try:
            token = await oauth.microsoft.authorize_access_token(request)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Authentication callback failed: {exc}",
            ) from exc
        claims = dict(token.get("userinfo") or {})
        profile = build_user_profile(claims)
        request.session[SESSION_USER_KEY] = profile.model_dump(mode="json")
        store_session_token(request, token, profile)
        return RedirectResponse(url="/ui")

    @app.get("/auth/logout")
    def auth_logout(request: Request):
        token_ref = str(request.session.get(SESSION_TOKEN_REF_KEY) or "").strip()
        if token_ref:
            token_cache = getattr(request.app.state, "session_token_cache", {})
            token_cache.pop(token_ref, None)
            request.app.state.session_token_cache = token_cache
            obo_cache = getattr(request.app.state, "obo_token_cache", {})
            obo_cache.pop(token_ref, None)
            request.app.state.obo_token_cache = obo_cache
        request.session.clear()
        if settings.auth_enabled:
            return RedirectResponse(url=microsoft_logout_url(settings))
        return RedirectResponse(url="/")

    @app.get("/api/me", response_model=UserProfile)
    def me_json(request: Request) -> UserProfile:
        if not settings.auth_enabled:
            return current_user(request)
        user = session_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not signed in.")
        return user

    @app.get("/me", response_class=HTMLResponse, response_model=None)
    def me(request: Request):
        if not settings.auth_enabled:
            return _profile_ui(current_user(request), auth_enabled=False)
        user = session_user(request)
        return _profile_ui(user, auth_enabled=True)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/health")
    def api_health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/api/tools/execute", response_model=ToolExecutionResponse)
    def api_tools_execute(
        payload: ToolExecutionRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> ToolExecutionResponse:
        needs_logs_token = payload.tool in {
            "query_monitor_metrics",
            "get_activity_logs",
            "get_vm_health",
            "investigate_incident",
        }
        management_token, logs_token = resolve_delegated_tokens(
            request,
            include_logs=needs_logs_token,
        )
        status, result, message = execute_tool_call(
            payload.tool,
            payload.arguments,
            management_token=management_token,
            logs_token=logs_token,
        )
        return ToolExecutionResponse(
            status=status,
            tool=payload.tool,
            result=result,
            message=message,
            supported_tools=supported_tools,
        )

    @app.get("/api/modules", response_model=list[ModuleDescriptor])
    def api_modules(_user: UserProfile = Depends(current_user)) -> list[ModuleDescriptor]:
        return module_descriptors

    @app.post("/api/modules/{module_id}/run", response_model=ModuleRunResponse)
    def api_modules_run(
        module_id: str,
        payload: ModuleRunRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> ModuleRunResponse:
        actions = module_action_map.get(module_id)
        if not actions:
            raise HTTPException(status_code=404, detail=f"Module '{module_id}' not found.")

        action = (payload.action or module_default_action[module_id]).strip()
        tool_name = actions.get(action)
        if not tool_name:
            available_actions = ", ".join(sorted(actions))
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported action '{action}' for module '{module_id}'. "
                f"Available actions: {available_actions}",
            )

        needs_logs_token = tool_name in {
            "query_monitor_metrics",
            "get_activity_logs",
            "get_vm_health",
            "investigate_incident",
        }
        management_token, logs_token = resolve_delegated_tokens(
            request,
            include_logs=needs_logs_token,
        )
        status, result, message = execute_tool_call(
            tool_name,
            payload.arguments,
            management_token=management_token,
            logs_token=logs_token,
        )
        return ModuleRunResponse(
            module=module_id,
            action=action,
            status=status,
            result=result,
            message=message,
        )

    @app.post("/api/chat", response_model=ChatResponse)
    def api_chat(
        payload: ChatRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> ChatResponse:
        suggested_tool = infer_tool_from_message(payload.message)
        if not suggested_tool:
            assistant_message = (
                "I can route this through operations tools. Try asking about resources, VM health, "
                "activity changes, incident investigation, security, or costs."
            )
            persisted_session_id = store.record_chat_exchange(
                session_id=payload.session_id,
                user=_user,
                user_message=payload.message,
                assistant_message=assistant_message,
                metadata={"suggested_tool": None, "tool_status": "not_routed"},
            )
            return ChatResponse(
                status="ok",
                message=assistant_message,
                session_id=persisted_session_id,
                suggested_tool=None,
                tool_result=None,
            )

        tool_arguments = infer_arguments_from_message(payload.message, suggested_tool)
        needs_logs_token = suggested_tool in {
            "query_monitor_metrics",
            "get_activity_logs",
            "get_vm_health",
            "investigate_incident",
        }
        management_token, logs_token = resolve_delegated_tokens(
            request,
            include_logs=needs_logs_token,
        )
        tool_status, tool_result, tool_message = execute_tool_call(
            suggested_tool,
            tool_arguments,
            management_token=management_token,
            logs_token=logs_token,
        )
        response_message = (
            f"Executed tool '{suggested_tool}' with status '{tool_status}'. "
            "Review tool_result for evidence and next actions."
        )
        if tool_message:
            response_message = f"{response_message} {tool_message}"
        persisted_session_id = store.record_chat_exchange(
            session_id=payload.session_id,
            user=_user,
            user_message=payload.message,
            assistant_message=response_message,
            metadata={
                "suggested_tool": suggested_tool,
                "tool_status": tool_status,
            },
        )

        return ChatResponse(
            status="ok",
            message=response_message,
            session_id=persisted_session_id,
            suggested_tool=suggested_tool,
            tool_result=tool_result,
        )

    @app.post("/alerts/azure-monitor", response_model=AlertIngestResponse)
    def ingest_azure_monitor_alert(payload: dict[str, Any]) -> AlertIngestResponse:
        return processor.ingest_azure_monitor_alert(payload)

    @app.get("/integrations/status", response_model=IntegrationStatus)
    def integration_status(_user: UserProfile = Depends(current_user)) -> IntegrationStatus:
        return integrations.status()

    @app.get("/integrations/azure/subscriptions", response_model=AzureSubscriptionListResponse)
    def list_azure_subscriptions(
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> AzureSubscriptionListResponse:
        management_token, _ = resolve_delegated_tokens(request, include_logs=False)
        return integrations.list_accessible_subscriptions(access_token=management_token)

    @app.get("/integrations/azure-openai/status", response_model=AzureOpenAIStatus)
    def azure_openai_status(_user: UserProfile = Depends(current_user)) -> AzureOpenAIStatus:
        return azure_openai.status()

    @app.get("/integrations/ai-search/status", response_model=AzureAISearchStatus)
    def ai_search_status(_user: UserProfile = Depends(current_user)) -> AzureAISearchStatus:
        return ai_search.status()

    @app.post("/integrations/azure-openai/test", response_model=AzureOpenAITestResponse)
    def azure_openai_test(
        request: AzureOpenAITestRequest,
        _user: UserProfile = Depends(current_user),
    ) -> AzureOpenAITestResponse:
        return azure_openai.test_chat(request.prompt)

    @app.post("/integrations/knowledge/ingest", response_model=KnowledgeIngestResponse)
    def knowledge_ingest(
        request: KnowledgeIngestRequest,
        _user: UserProfile = Depends(current_user),
    ) -> KnowledgeIngestResponse:
        return ai_search.ingest_local_knowledge(
            source_paths=request.source_paths,
            max_files=request.max_files,
            force_reindex=request.force_reindex,
        )

    @app.post("/integrations/knowledge/query", response_model=KnowledgeQueryResponse)
    def knowledge_query(
        request: KnowledgeQueryRequest,
        _user: UserProfile = Depends(current_user),
    ) -> KnowledgeQueryResponse:
        return ai_search.query_knowledge(
            query=request.query,
            top=request.top,
            use_ai_summary=request.use_ai_summary,
        )

    @app.post("/integrations/log-analytics/query", response_model=LogAnalyticsQueryResponse)
    def query_log_analytics(
        payload: LogAnalyticsQueryRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> LogAnalyticsQueryResponse:
        management_token, logs_token = resolve_delegated_tokens(request, include_logs=True)
        return integrations.query_log_analytics(
            payload,
            access_token=management_token,
            logs_access_token=logs_token,
        )

    @app.post("/integrations/log-analytics/analyze", response_model=LogAnalyticsAnalyzeResponse)
    def analyze_log_analytics(
        payload: LogAnalyticsAnalyzeRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> LogAnalyticsAnalyzeResponse:
        management_token, logs_token = resolve_delegated_tokens(request, include_logs=True)
        query_result = integrations.query_log_analytics(
            payload,
            access_token=management_token,
            logs_access_token=logs_token,
        )
        return azure_openai.analyze_log_rows(
            query_result=query_result,
            prompt=payload.prompt,
            max_rows=payload.max_rows,
        )

    @app.post("/integrations/log-analytics/poll-alerts", response_model=list[AlertIngestResponse])
    def poll_log_analytics_alerts(
        payload: AlertPollRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> list[AlertIngestResponse]:
        management_token, logs_token = resolve_delegated_tokens(request, include_logs=True)
        query_result = integrations.poll_workspace_alert_signals(
            payload,
            access_token=management_token,
            logs_access_token=logs_token,
        )
        if query_result.status in {"error", "not_configured"}:
            raise HTTPException(status_code=400, detail=query_result.message)
        responses = []
        for row in query_result.rows:
            if is_log_analytics_incident_signal(row):
                responses.append(processor.ingest_log_analytics_signal(row))
        return responses

    @app.post("/integrations/resource-graph/discover", response_model=ResourceDiscoveryResponse)
    def discover_resources(
        payload: ResourceDiscoveryRequest,
        request: Request,
        _user: UserProfile = Depends(current_user),
    ) -> ResourceDiscoveryResponse:
        management_token, _ = resolve_delegated_tokens(request, include_logs=False)
        return integrations.discover_resources(payload, access_token=management_token)

    @app.get("/incidents", response_model=list[Incident])
    def list_incidents(_user: UserProfile = Depends(current_user)) -> list[Incident]:
        return store.list_incidents()

    @app.get("/incidents/{incident_id}", response_model=Incident)
    def get_incident(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> Incident:
        incident = store.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.get("/incidents/{incident_id}/actions", response_model=list[RemediationAction])
    def list_incident_actions(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> list[RemediationAction]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_actions_for_incident(incident_id)

    @app.get("/incidents/{incident_id}/audit", response_model=list[AuditEvent])
    def list_incident_audit(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> list[AuditEvent]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_audit_events(incident_id)

    @app.post("/incidents/{incident_id}/approve")
    def approve_incident(
        incident_id: str,
        request: ApproveRequest,
        _user: UserProfile = Depends(current_user),
    ):
        try:
            return executor.approve_incident(incident_id, request.approver, request.comment)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/incidents/{incident_id}/reject", response_model=Incident)
    def reject_incident(
        incident_id: str,
        request: RejectRequest,
        _user: UserProfile = Depends(current_user),
    ) -> Incident:
        try:
            return executor.reject_incident(incident_id, request.rejected_by, request.reason)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/actions/{action_id}", response_model=RemediationAction)
    def get_action(
        action_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> RemediationAction:
        action = store.get_action(action_id)
        if not action:
            raise HTTPException(status_code=404, detail="Action not found")
        return action

    @app.get("/ui", response_class=HTMLResponse, response_model=None)
    def ui(request: Request):
        if settings.auth_enabled and not session_user(request):
            return RedirectResponse(url="/auth/login")
        return _approval_ui(session_user(request), auth_enabled=settings.auth_enabled)

    return app


def _status_ui(status: dict[str, Any]) -> str:
    runtime = status["runtime"]
    auth = status["auth"]
    integrations = status["azure_integrations"]
    azure_openai = status["azure_openai"]
    auth_state = "Enabled" if auth["enabled"] else "Disabled"
    auth_config = "Configured" if auth["configured"] else "Not configured"
    integration_mode = integrations["mode"].replace("_", " ").title()
    live_reads = "Enabled" if integrations["live_azure_integrations_enabled"] else "Disabled"
    log_analytics = "Configured" if integrations["log_analytics_configured"] else "Not configured"
    openai = "Configured" if azure_openai["configured"] else "Not configured"

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Service Status - Azure AIOps Agent</title>
  <style>
    :root {{
      font-family: Segoe UI, system-ui, sans-serif;
      color: #0d2033;
      background: #f5f8fb;
      --mds-brand-deep: #002b45;
      --mds-brand-main: #1267a8;
      --mds-brand-accent: #42b0d5;
      --mds-surface: #ffffff;
      --mds-border: #d2deea;
      --mds-muted: #4c6478;
      --mds-success: #116149;
      --mds-radius-sm: 6px;
      --mds-radius-md: 8px;
    }}
    body {{ margin: 0; background: #f5f8fb; color: #0d2033; }}
    header {{ background: var(--mds-brand-deep); color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
    header h1 {{ font-size: 20px; margin: 0; }}
    nav {{ display: flex; gap: 14px; flex-wrap: wrap; }}
    nav a {{ color: white; text-decoration: none; font-weight: 600; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 28px 24px; }}
    .hero {{ background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 24px; display: flex; justify-content: space-between; gap: 20px; flex-wrap: wrap; }}
    .hero h2 {{ margin: 0 0 8px; font-size: 26px; }}
    .muted {{ color: var(--mds-muted); }}
    .badge {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 6px 10px; background: #e8f4ef; color: var(--mds-success); font-weight: 700; font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 18px; }}
    .panel {{ background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 18px; min-width: 0; }}
    .label {{ color: var(--mds-muted); font-size: 12px; text-transform: uppercase; font-weight: 700; margin-bottom: 8px; }}
    .value {{ overflow-wrap: anywhere; font-size: 15px; }}
    .actions {{ display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }}
    a.button {{ background: var(--mds-brand-main); color: white; text-decoration: none; border-radius: var(--mds-radius-sm); padding: 10px 14px; font-weight: 600; }}
    a.button.secondary {{ background: #eef4f8; color: #17466d; border: 1px solid var(--mds-border); }}
    a:focus-visible {{ outline: 2px solid var(--mds-brand-accent); outline-offset: 2px; }}
    ul {{ margin: 10px 0 0; padding-left: 18px; }}
    li {{ margin: 6px 0; }}
  </style>
</head>
<body>
  <header>
    <h1>Azure AIOps Agent</h1>
    <nav>
      <a href="/me">Profile</a>
      <a href="/ui">Incidents</a>
      <a href="/docs">API Docs</a>
      <a href="/api/status">JSON</a>
    </nav>
  </header>
  <main>
    <section class="hero">
      <div>
        <h2>Service Status</h2>
        <div class="muted">Python {html.escape(runtime["python_version"])} | FastAPI | {html.escape(status["environment"])}</div>
      </div>
      <div class="badge">{html.escape(status["execution_mode"]).title()} Mode</div>
    </section>
    <section class="grid" aria-label="Service status details">
      <div class="panel"><div class="label">Authentication</div><div class="value">{auth_state} | {auth_config}</div></div>
      <div class="panel"><div class="label">Authority</div><div class="value">{_escape(auth["authority"])}</div></div>
      <div class="panel"><div class="label">Azure Integration Mode</div><div class="value">{integration_mode}</div></div>
      <div class="panel"><div class="label">Live Azure Reads</div><div class="value">{live_reads}</div></div>
      <div class="panel"><div class="label">Subscriptions</div><div class="value">{integrations["subscriptions_configured"]}</div></div>
      <div class="panel"><div class="label">Workspace Mappings</div><div class="value">{integrations["log_analytics_workspace_mappings_configured"]}</div></div>
      <div class="panel"><div class="label">Log Analytics</div><div class="value">{log_analytics}</div></div>
      <div class="panel"><div class="label">Azure OpenAI</div><div class="value">{openai}</div></div>
      <div class="panel"><div class="label">OpenAI Deployment</div><div class="value">{_escape(azure_openai["deployment"] or "Not configured")}</div></div>
      <div class="panel"><div class="label">OpenAI Auth Mode</div><div class="value">{_escape(azure_openai["auth_mode"])}</div></div>
    </section>
    <section class="grid" aria-label="Capabilities">
      <div class="panel">
        <div class="label">Ingestion</div>
        <ul>{_list_items(integrations["supported_ingestion_modes"])}</ul>
      </div>
      <div class="panel">
        <div class="label">Resources</div>
        <ul>{_list_items(integrations["supported_resource_types"])}</ul>
      </div>
    </section>
    <div class="actions">
      <a class="button" href="/me">View Profile</a>
      <a class="button secondary" href="/ui">Open Incidents</a>
      <a class="button secondary" href="/docs">API Docs</a>
      <a class="button secondary" href="/integrations/azure-openai/status">Azure OpenAI JSON</a>
      <a class="button secondary" href="/auth/status">Auth JSON</a>
    </div>
  </main>
</body>
</html>
"""


def _list_items(values: list[str]) -> str:
    return "".join(f"<li>{_escape(value)}</li>" for value in values)


def _profile_ui(user: UserProfile | None, auth_enabled: bool) -> str:
    if user is None:
        return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Profile - Azure AIOps Agent</title>
  <style>
    :root {
      font-family: Segoe UI, system-ui, sans-serif;
      color: #0d2033;
      background: #f5f8fb;
      --mds-brand-deep: #002b45;
      --mds-brand-main: #1267a8;
      --mds-brand-accent: #42b0d5;
      --mds-surface: #ffffff;
      --mds-border: #d2deea;
      --mds-radius-sm: 6px;
      --mds-radius-md: 8px;
    }
    body { margin: 0; background: #f5f8fb; color: #0d2033; }
    header { background: var(--mds-brand-deep); color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
    header h1 { font-size: 20px; margin: 0; }
    main { max-width: 920px; margin: 0 auto; padding: 28px 24px; }
    .panel { background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 24px; }
    .actions { display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }
    a.button { background: var(--mds-brand-main); color: white; text-decoration: none; border-radius: var(--mds-radius-sm); padding: 10px 14px; font-weight: 600; }
    a:focus-visible { outline: 2px solid var(--mds-brand-accent); outline-offset: 2px; }
    a.secondary { color: #17466d; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <header><h1>Azure AIOps Agent</h1><a class="secondary" style="color:white" href="/docs">API Docs</a></header>
  <main>
    <section class="panel">
      <h2>Not Signed In</h2>
      <p>Sign in with Microsoft to view your profile and access operator actions.</p>
      <div class="actions">
        <a class="button" href="/auth/login">Sign In</a>
        <a class="secondary" href="/">Service Status</a>
      </div>
    </section>
  </main>
</body>
</html>
"""

    name = _escape(user.name or user.username or "Operator")
    username = _escape(user.username or "")
    email = _escape(user.email or "")
    object_id = _escape(user.object_id or "")
    tenant_id = _escape(user.tenant_id or "")
    initials = _initials(user.name or user.username or "Operator")
    auth_mode = "Microsoft Entra ID" if auth_enabled else "Local development"
    sign_out = '<a class="button danger" href="/auth/logout">Sign Out</a>' if auth_enabled else ""

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Profile - Azure AIOps Agent</title>
  <style>
    :root {{
      font-family: Segoe UI, system-ui, sans-serif;
      color: #0d2033;
      background: #f5f8fb;
      --mds-brand-deep: #002b45;
      --mds-brand-main: #1267a8;
      --mds-brand-accent: #42b0d5;
      --mds-surface: #ffffff;
      --mds-border: #d2deea;
      --mds-muted: #4c6478;
      --mds-danger: #a83232;
      --mds-radius-sm: 6px;
      --mds-radius-md: 8px;
    }}
    body {{ margin: 0; background: #f5f8fb; color: #0d2033; }}
    header {{ background: var(--mds-brand-deep); color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
    header h1 {{ font-size: 20px; margin: 0; }}
    nav {{ display: flex; gap: 14px; flex-wrap: wrap; }}
    nav a {{ color: white; text-decoration: none; font-weight: 600; }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 28px 24px; }}
    .summary {{ display: grid; grid-template-columns: auto 1fr; gap: 18px; align-items: center; background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 24px; }}
    .avatar {{ width: 76px; height: 76px; border-radius: 50%; background: var(--mds-brand-main); color: white; display: grid; place-items: center; font-size: 26px; font-weight: 700; }}
    h2 {{ margin: 0 0 6px; font-size: 24px; }}
    .muted {{ color: var(--mds-muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 18px; }}
    .field {{ background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 16px; min-width: 0; }}
    .label {{ color: var(--mds-muted); font-size: 12px; text-transform: uppercase; font-weight: 700; margin-bottom: 8px; }}
    .value {{ overflow-wrap: anywhere; font-size: 15px; }}
    .actions {{ display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }}
    a.button {{ background: var(--mds-brand-main); color: white; text-decoration: none; border-radius: var(--mds-radius-sm); padding: 10px 14px; font-weight: 600; }}
    a.button.secondary {{ background: #eef4f8; color: #17466d; border: 1px solid var(--mds-border); }}
    a.button.danger {{ background: var(--mds-danger); }}
    a:focus-visible {{ outline: 2px solid var(--mds-brand-accent); outline-offset: 2px; }}
  </style>
</head>
<body>
  <header>
    <h1>Azure AIOps Agent</h1>
    <nav>
      <a href="/ui">Incidents</a>
      <a href="/docs">API Docs</a>
      <a href="/api/me">JSON</a>
    </nav>
  </header>
  <main>
    <section class="summary">
      <div class="avatar">{initials}</div>
      <div>
        <h2>{name}</h2>
        <div class="muted">{email or username}</div>
        <div class="actions">
          <a class="button" href="/ui">Open Incidents</a>
          <a class="button secondary" href="/">Service Status</a>
          {sign_out}
        </div>
      </div>
    </section>
    <section class="grid" aria-label="Profile details">
      <div class="field"><div class="label">Authentication</div><div class="value">{auth_mode}</div></div>
      <div class="field"><div class="label">Username</div><div class="value">{username or "Not provided"}</div></div>
      <div class="field"><div class="label">Email</div><div class="value">{email or "Not provided"}</div></div>
      <div class="field"><div class="label">Tenant ID</div><div class="value">{tenant_id or "Not provided"}</div></div>
      <div class="field"><div class="label">Object ID</div><div class="value">{object_id or "Not provided"}</div></div>
      <div class="field"><div class="label">Session</div><div class="value">Browser session active</div></div>
    </section>
  </main>
</body>
</html>
"""


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def _initials(value: str) -> str:
    parts = [part for part in value.replace("@", " ").replace(".", " ").split() if part]
    letters = "".join(part[0] for part in parts[:2]).upper()
    return html.escape(letters or "OP", quote=True)


def _approval_ui(user: UserProfile | None = None, auth_enabled: bool = False) -> str:
    display_name = _escape(user.name or user.username) if user else "Local operator"
    auth_link = '<a href="/auth/logout">Sign Out</a>' if auth_enabled else ""
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Azure AIOps Agent</title>
  <style>
    :root {
      font-family: Segoe UI, system-ui, sans-serif;
      color: #0d2033;
      background: #f5f8fb;
      --mds-brand-deep: #002b45;
      --mds-brand-main: #1267a8;
      --mds-brand-accent: #42b0d5;
      --mds-surface: #ffffff;
      --mds-border: #d2deea;
      --mds-muted: #4c6478;
      --mds-success: #127a5b;
      --mds-danger: #a83232;
      --mds-radius-sm: 6px;
      --mds-radius-md: 8px;
    }
    body { margin: 0; background: #f5f8fb; color: #0d2033; }
    header { background: var(--mds-brand-deep); color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 18px; flex-wrap: wrap; }
    header h1 { margin: 0; font-size: 24px; }
    nav { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
    nav a { color: white; text-decoration: none; font-weight: 600; }
    .user { color: #d7e8f7; font-size: 14px; }
    main { max-width: 1160px; margin: 0 auto; padding: 24px; }
    .layout { display: grid; grid-template-columns: 1.45fr 1fr; gap: 18px; align-items: start; }
    @media (max-width: 980px) { .layout { grid-template-columns: 1fr; } }
    .panel { background: var(--mds-surface); border: 1px solid var(--mds-border); border-radius: var(--mds-radius-md); padding: 12px; }
    .panel h2 { margin: 0 0 12px; font-size: 18px; }
    table { width: 100%; border-collapse: collapse; background: var(--mds-surface); border: 1px solid var(--mds-border); }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e6edf5; vertical-align: top; }
    th { background: #edf3f8; font-size: 13px; text-transform: uppercase; }
    button { border: 0; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    .approve { background: var(--mds-success); color: white; }
    .reject { background: var(--mds-danger); color: white; }
    .secondary { background: #d9e1ec; color: #17344f; border: 1px solid var(--mds-border); }
    .muted { color: var(--mds-muted); }
    .actions { display: flex; gap: 8px; }
    .chat-log { min-height: 320px; max-height: 520px; overflow-y: auto; border: 1px solid var(--mds-border); padding: 10px; background: #f8fbff; border-radius: var(--mds-radius-md); }
    .chat-msg { margin-bottom: 10px; padding: 8px 10px; border: 1px solid var(--mds-border); background: var(--mds-surface); border-radius: var(--mds-radius-sm); }
    .chat-msg .who { font-size: 12px; color: var(--mds-muted); margin-bottom: 4px; text-transform: uppercase; }
    .chat-msg pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 8px 0 0; background: #eef4f8; padding: 8px; }
    .chat-input { width: 100%; box-sizing: border-box; margin-top: 10px; border: 1px solid #c9d6e4; padding: 10px; font: inherit; resize: vertical; min-height: 96px; border-radius: var(--mds-radius-sm); }
    .chat-actions { margin-top: 10px; display: flex; gap: 8px; }
    a:focus-visible, button:focus-visible, textarea:focus-visible { outline: 2px solid var(--mds-brand-accent); outline-offset: 2px; }
  </style>
</head>
<body>
  <header>
    <h1>Azure AIOps Agent</h1>
    <nav aria-label="Primary">
      <span class="user">__DISPLAY_NAME__</span>
      <a href="/">Status</a>
      <a href="/me">Profile</a>
      <a href="/ui#chat">Chat</a>
      <a href="/docs">API Docs</a>
      <a href="/api/status">JSON</a>
      __AUTH_LINK__
    </nav>
  </header>
  <main>
    <div class="layout">
      <section class="panel">
        <h2>Incident Approvals</h2>
        <table>
          <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Summary</th><th>Actions</th></tr></thead>
          <tbody id="incidents"></tbody>
        </table>
      </section>
      <section class="panel" id="chat">
        <h2>Copilot Chat</h2>
        <div id="chatLog" class="chat-log"></div>
        <textarea id="chatInput" class="chat-input" placeholder="Ask about resources, incidents, security, cost, or runbooks..."></textarea>
        <div class="chat-actions">
          <button class="approve" id="chatSend" onclick="sendChat()">Send</button>
          <button class="secondary" onclick="clearChat()">Clear</button>
        </div>
      </section>
    </div>
  </main>
  <script>
    const CHAT_SESSION_KEY = 'aiops_chat_session_id';
    function appendChat(role, text, toolResult) {
      const chatLog = document.getElementById('chatLog');
      const box = document.createElement('div');
      box.className = 'chat-msg';
      const who = document.createElement('div');
      who.className = 'who';
      who.textContent = role;
      const body = document.createElement('div');
      body.textContent = text || '';
      box.appendChild(who);
      box.appendChild(body);
      if (toolResult) {
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = 'Tool Result';
        const pre = document.createElement('pre');
        pre.textContent = JSON.stringify(toolResult, null, 2);
        details.appendChild(summary);
        details.appendChild(pre);
        box.appendChild(details);
      }
      chatLog.appendChild(box);
      chatLog.scrollTop = chatLog.scrollHeight;
    }

    async function load() {
      const rows = document.getElementById('incidents');
      const incidents = await fetch('/incidents').then(r => r.json());
      rows.innerHTML = incidents.map(i => `
        <tr>
          <td><strong>${i.title}</strong><br><span class="muted">${i.id}</span></td>
          <td>${i.severity}</td>
          <td>${i.status}</td>
          <td>${i.summary}</td>
          <td class="actions">
            <button class="approve" onclick="approve('${i.id}')">Approve</button>
            <button class="reject" onclick="rejectIncident('${i.id}')">Reject</button>
          </td>
        </tr>`).join('');
    }

    async function approve(id) {
      const approver = prompt('Approver email');
      if (!approver) return;
      await fetch(`/incidents/${id}/approve`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({approver, comment: 'Approved from UI'})
      });
      load();
    }
    async function rejectIncident(id) {
      const rejected_by = prompt('Reviewer email');
      const reason = prompt('Reason');
      if (!rejected_by || !reason) return;
      await fetch(`/incidents/${id}/reject`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rejected_by, reason})
      });
      load();
    }

    async function sendChat() {
      const input = document.getElementById('chatInput');
      const sendButton = document.getElementById('chatSend');
      const message = (input.value || '').trim();
      if (!message) return;

      appendChat('You', message);
      input.value = '';
      sendButton.disabled = true;
      try {
        const sessionId = localStorage.getItem(CHAT_SESSION_KEY);
        const response = await fetch('/api/chat', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({message, session_id: sessionId || null})
        });
        const data = await response.json();
        if (data.session_id) {
          localStorage.setItem(CHAT_SESSION_KEY, data.session_id);
        }
        if (!response.ok) {
          appendChat('Copilot', data.detail || 'Chat failed.');
          return;
        }
        appendChat('Copilot', data.message || '', data.tool_result || null);
      } catch (error) {
        appendChat('Copilot', `Chat failed: ${error}`);
      } finally {
        sendButton.disabled = false;
      }
    }

    function clearChat() {
      localStorage.removeItem(CHAT_SESSION_KEY);
      document.getElementById('chatLog').innerHTML = '';
    }

    document.getElementById('chatInput').addEventListener('keydown', function (event) {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        sendChat();
      }
    });

    load();
  </script>
</body>
</html>
""".replace("__DISPLAY_NAME__", display_name).replace("__AUTH_LINK__", auth_link)
