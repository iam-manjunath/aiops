from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class IncidentStatus(str, Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    REJECTED = "rejected"
    FAILED = "failed"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ActionType(str, Enum):
    RESTART_VM = "restart_vm"
    RESIZE_VMSS = "resize_vmss"
    RUN_AUTOMATION_WEBHOOK = "run_automation_webhook"
    ADJUST_AUTOSCALE_RULE = "adjust_autoscale_rule"
    CREATE_TICKET = "create_ticket"
    MANUAL_ACTION_REQUIRED = "manual_action_required"


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    rule_name: str
    severity: str
    signal_type: str | None = None
    monitor_condition: str | None = None
    monitoring_service: str | None = None
    fired_at: datetime = Field(default_factory=utcnow)
    description: str | None = None
    resource_ids: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_resource_id(self) -> str | None:
        return self.resource_ids[0] if self.resource_ids else None

    @property
    def is_security_alert(self) -> bool:
        haystack = " ".join(
            [
                self.rule_name,
                self.signal_type or "",
                self.monitoring_service or "",
                self.description or "",
            ]
        ).lower()
        return any(token in haystack for token in ["sentinel", "defender", "security", "threat"])


class RemediationAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    incident_id: str
    type: ActionType
    status: ActionStatus = ActionStatus.PROPOSED
    risk: RiskLevel
    description: str
    affected_resources: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    rollback: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    proposed_at: datetime = Field(default_factory=utcnow)
    approved_by: str | None = None
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    execution_output: str | None = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: str
    source: str = "azure-monitor"
    alert_rule: str
    resource_ids: list[str] = Field(default_factory=list)
    summary: str
    blast_radius: str
    likely_causes: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    action_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    tags: dict[str, str] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    incident_id: str | None = None
    action_id: str | None = None
    event_type: str
    actor: str = "system"
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class IncidentRecommendation(BaseModel):
    summary: str
    blast_radius: str
    likely_causes: list[str]
    actions: list[RemediationAction]
    model_metadata: dict[str, Any] = Field(default_factory=dict)


class ApproveRequest(BaseModel):
    approver: str
    comment: str | None = None


class RejectRequest(BaseModel):
    rejected_by: str
    reason: str


class AlertIngestResponse(BaseModel):
    incident_id: str
    action_ids: list[str]
    status: IncidentStatus


class ActionExecutionResult(BaseModel):
    action_id: str
    status: ActionStatus
    output: str


class IntegrationStatus(BaseModel):
    mode: str
    live_azure_integrations_enabled: bool
    subscriptions_configured: int
    log_analytics_configured: bool
    log_analytics_workspace_mappings_configured: int
    azure_openai_configured: bool
    supported_ingestion_modes: list[str]
    supported_resource_types: list[str]


class AzureSubscription(BaseModel):
    subscription_id: str
    display_name: str | None = None
    state: str | None = None
    tenant_id: str | None = None


class AzureSubscriptionListResponse(BaseModel):
    status: str
    source: str
    subscriptions: list[AzureSubscription] = Field(default_factory=list)
    message: str | None = None


class LogAnalyticsQueryRequest(BaseModel):
    query: str
    subscription_id: str | None = None
    workspace_id: str | None = None
    timespan_minutes: int | None = None


class LogAnalyticsQueryResponse(BaseModel):
    status: str
    workspace_id: str | None
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


class LogAnalyticsAnalyzeRequest(LogAnalyticsQueryRequest):
    prompt: str = (
        "Analyze these Azure Log Analytics rows for operational risk, likely causes, "
        "and recommended next steps."
    )
    max_rows: int = 50


class LogAnalyticsAnalyzeResponse(BaseModel):
    query_status: str
    analysis_status: str
    workspace_id: str | None
    row_count: int
    columns: list[str] = Field(default_factory=list)
    analysis: str | None = None
    message: str | None = None


class ResourceDiscoveryRequest(BaseModel):
    subscriptions: list[str] | None = None
    resource_types: list[str] = Field(
        default_factory=lambda: [
            "microsoft.compute/virtualmachines",
            "microsoft.compute/virtualmachinescalesets",
            "microsoft.containerservice/managedclusters",
        ]
    )
    limit: int = 100


class ResourceDiscoveryResponse(BaseModel):
    status: str
    subscriptions: list[str]
    query: str
    resources: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


class AlertPollRequest(BaseModel):
    query: str | None = None
    subscription_id: str | None = None
    workspace_id: str | None = None
    timespan_minutes: int | None = None
    max_alerts: int = 50


class AuthStatus(BaseModel):
    enabled: bool
    configured: bool
    authority: str
    login_url: str
    logout_url: str
    profile_url: str


class UserProfile(BaseModel):
    authenticated: bool
    name: str | None = None
    username: str | None = None
    email: str | None = None
    object_id: str | None = None
    tenant_id: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


class AzureOpenAIStatus(BaseModel):
    enabled: bool
    configured: bool
    endpoint_configured: bool
    deployment_configured: bool
    api_version: str
    auth_mode: str
    api_key_configured: bool
    deployment: str | None = None
    message: str


class AzureAISearchStatus(BaseModel):
    enabled: bool
    configured: bool
    endpoint_configured: bool
    index_configured: bool
    auth_mode: str
    api_key_configured: bool
    endpoint: str | None = None
    index: str | None = None
    message: str


class AzureOpenAITestRequest(BaseModel):
    prompt: str = "Return one short sentence confirming Azure OpenAI connectivity."


class AzureOpenAITestResponse(BaseModel):
    status: str
    provider: str
    deployment: str | None = None
    output: str | None = None
    message: str | None = None


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    status: str
    message: str
    session_id: str | None = None
    suggested_tool: str | None = None
    tool_result: dict[str, Any] | None = None


class ToolExecutionRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResponse(BaseModel):
    status: str
    tool: str
    result: dict[str, Any] | None = None
    message: str | None = None
    supported_tools: list[str] = Field(default_factory=list)


class ModuleDescriptor(BaseModel):
    id: str
    title: str
    purpose: str
    primary_tools: list[str] = Field(default_factory=list)
    status: str


class ModuleRunRequest(BaseModel):
    action: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)


class ModuleRunResponse(BaseModel):
    module: str
    action: str
    status: str
    result: dict[str, Any] | None = None
    message: str | None = None


class KnowledgeIngestRequest(BaseModel):
    source_paths: list[str] | None = None
    max_files: int = 200
    force_reindex: bool = False


class KnowledgeIngestResponse(BaseModel):
    status: str
    index: str | None = None
    document_count: int = 0
    indexed_count: int = 0
    failed_count: int = 0
    sources: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    message: str | None = None


class KnowledgeQueryRequest(BaseModel):
    query: str
    top: int = 5
    use_ai_summary: bool = True


class KnowledgeQueryResponse(BaseModel):
    status: str
    index: str | None = None
    query: str
    hit_count: int = 0
    hits: list[dict[str, Any]] = Field(default_factory=list)
    answer: str | None = None
    message: str | None = None
