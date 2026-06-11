# Specification Alignment (June 11, 2026)

This document maps the current implementation to `Specification.md` and highlights what is already available, what is partially covered, and what should be added next.

## Implemented Now

- FastAPI backend with Microsoft Entra ID login support.
- Azure OpenAI integration with connectivity test and Log Analytics analysis.
- Azure Resource Graph resource discovery for VM, VMSS, and AKS.
- Azure Monitor/Log Analytics ingestion, polling, and incident creation.
- Approval-gated remediation workflow with audit trail.
- Pluggable persistence backend with local JSON and PostgreSQL support (`AIOPS_STATE_BACKEND`).
- API contract additions requested in the specification:
  - `POST /api/chat`
  - `GET /api/health`
  - `POST /api/tools/execute`
- Spec-style tool names are now accepted by `POST /api/tools/execute`:
  - `search_resources`
  - `get_vm_health`
  - `query_monitor_metrics`
  - `get_activity_logs`
  - `check_nsg_rules`
  - `investigate_incident`
  - `get_cost_analysis` (extension point)
  - `get_security_findings` (extension point)
  - `restart_vm` (extension point)
  - `start_vm` (extension point)
  - `stop_vm` (extension point)
  - `create_snapshot` (extension point)
  - `run_automation_runbook` (extension point)

## Partially Covered

- Incident RCA Agent:
  - Covered through alert ingestion, context collection, and model-assisted analysis.
  - Needs richer timeline synthesis and explicit corrective/preventive sections.
- Automation Agent:
  - Approval and execution framework exists.
  - Action catalog does not yet include `start_vm`, `stop_vm`, and `create_snapshot`.
- Network Troubleshooting Agent:
  - Resource discovery and NSG inventory support exist.
  - Deep checks (route table effective routes, DNS test, load balancer probe diagnostics) are not yet implemented.
- VM Health Agent:
  - Log Analytics-based checks are available.
  - Boot diagnostics and extension/guest agent checks are not yet implemented.

## Not Implemented Yet

- Full relational schema from the specification (`users`, `chat_sessions`, dedicated incident relational model).
- Azure AI Search + RAG knowledge base ingestion/query.
- Cost Management API integration for trend and rightsizing analysis.
- Defender for Cloud + Azure Policy evidence enrichment.
- Teams app channel and Teams message action integration.
- Full React/Next.js frontend (current UI is server-rendered HTML).

## Recommended Next Changes

1. Implement full `users` and `chat_sessions` tables with identity-to-session linkage for `/api/chat`.
2. Implement Cost Management and Defender/Policy clients behind the existing tool dispatcher.
3. Add first RAG pipeline with Azure AI Search index + document ingestion job for SOPs/runbooks.
4. Expand remediation catalog to include `start_vm`, `stop_vm`, and `create_snapshot` with explicit guardrails and rollback notes.
5. Add Teams integration for approval actions and incident notifications.

## Notes

- `Specification.md` references GPT-4.1 / GPT-4o. The current implementation already supports Azure OpenAI deployments via environment config, so you can keep `gpt-5.x` or switch deployment names per environment without code changes.
- `.env` is restored from `.env.example`; production credentials must be re-entered.
