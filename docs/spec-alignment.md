# Specification Alignment (June 11, 2026)

This document maps the current implementation to `Specification.md` and highlights what is already available, what is partially covered, and what should be added next.

## Implemented Now

- FastAPI backend with Microsoft Entra ID login support.
- Azure OpenAI integration with connectivity test and Log Analytics analysis.
- Azure Resource Graph resource discovery for VM, VMSS, and AKS.
- Azure Monitor/Log Analytics ingestion, polling, and incident creation.
- Approval-gated remediation workflow with audit trail.
- Pluggable persistence backend with local JSON and PostgreSQL support (`AIOPS_STATE_BACKEND`).
- Relational persistence for `users` and `chat_sessions` with `/api/chat` session tracking.
- Azure AI Search knowledge ingestion/query with RAG-style answer synthesis via Azure OpenAI.
- API contract additions requested in the specification:
  - `POST /api/chat`
  - `GET /api/health`
  - `POST /api/tools/execute`
  - `GET /api/modules`
  - `POST /api/modules/{module_id}/run`
- All nine specification modules are now exposed as first-class module APIs:
  - `resource_discovery_agent`
  - `vm_health_agent`
  - `network_troubleshooting_agent`
  - `cost_optimization_agent`
  - `security_agent`
  - `change_investigation_agent`
  - `incident_rca_agent`
  - `knowledge_base_agent`
  - `automation_agent`
- Spec-style tool names are now accepted by `POST /api/tools/execute`:
  - `search_resources`
  - `get_vm_health`
  - `query_monitor_metrics`
  - `get_activity_logs`
  - `check_nsg_rules`
  - `investigate_incident`
  - `get_cost_analysis` (Azure Cost Management query integration)
  - `get_security_findings` (Defender assessment findings via Resource Graph)
  - `restart_vm`
  - `start_vm`
  - `stop_vm`
  - `create_snapshot`
  - `run_automation_runbook`

## Partially Covered

- Incident RCA Agent:
  - Covered through alert ingestion, context collection, and model-assisted analysis.
  - Needs richer timeline synthesis and explicit corrective/preventive sections.
- Automation Agent:
  - Approval and execution framework exists.
  - Module/tool actions `start_vm`, `stop_vm`, `create_snapshot`, and `run_automation_runbook` are exposed, but direct execution currently routes through approval-gated remediation boundaries and live adapters remain extension points.
- Network Troubleshooting Agent:
  - Resource discovery and NSG inventory support exist.
  - Deep checks (route table effective routes, DNS test, load balancer probe diagnostics) are not yet implemented.
- VM Health Agent:
  - Log Analytics-based checks are available.
  - Boot diagnostics and extension/guest agent checks are not yet implemented.

## Not Implemented Yet

- Dedicated `chat_messages` history table (current model stores session summary and message counts in `chat_sessions`).
- Advanced RAG features (chunking strategy, embeddings/vector fields, and citation scoring).
- Defender for Cloud + Azure Policy deeper evidence enrichment (current: Defender assessments via `securityresources` query path).
- Teams app channel and Teams message action integration.
- Full React/Next.js frontend (current UI is server-rendered HTML).

## Recommended Next Changes

1. Add optional `chat_messages` table for full conversational history and analytics.
2. Expand cost/security analysis output with trends, anomaly scoring, and policy correlation.
3. Expand remediation catalog to include `start_vm`, `stop_vm`, and `create_snapshot` with explicit guardrails and rollback notes.
4. Add Teams integration for approval actions and incident notifications.
5. Add optional vector index + embeddings pipeline for hybrid search ranking.

## Notes

- `Specification.md` references GPT-4.1 / GPT-4o. The current implementation already supports Azure OpenAI deployments via environment config, so you can keep `gpt-5.x` or switch deployment names per environment without code changes.
- `.env` is restored from `.env.example`; production credentials must be re-entered.
