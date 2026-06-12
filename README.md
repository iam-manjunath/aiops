# Azure AIOps Agent

Azure-native AIOps MVP for VMs and VM Scale Sets. The agent ingests Azure Monitor alerts, enriches them with Azure context, proposes AI-assisted remediation, and executes only after human approval.

## What Is Included

- FastAPI control plane with approval-gated remediation.
- Deterministic local analyzer with optional Azure OpenAI recommendations.
- Azure Monitor Action Group webhook ingestion.
- Log Analytics KQL query and alert-signal polling endpoints.
- Resource Graph discovery for existing VM, VMSS, and AKS resources.
- Tool execution handlers for Azure Cost analysis and security findings.
- Azure adapter boundaries for Monitor/Log Analytics, Resource Graph, Advisor, Compute, Automation, and Sentinel enrichment.
- Bicep infrastructure scaffold for Azure Container Apps, managed identity, Log Analytics, Application Insights, Service Bus, Storage, and Key Vault.
- Architecture and remediation catalog docs.
- Unit and contract tests with sample Azure Monitor payloads.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
copy .env.example .env
uvicorn aiops_agent.app:create_app --factory --reload
```

Open `http://127.0.0.1:8000/docs` for the API.

For a handoff-friendly setup guide, see `docs/python-environment.md`.
For Microsoft Entra ID login setup, see `docs/microsoft-login.md`.
For Azure OpenAI setup, see `docs/azure-openai.md`.
For Azure AI Search RAG setup, see `docs/ai-search-rag.md`.
For current spec coverage and next implementation priorities, see `docs/spec-alignment.md`.
For UI conventions, see `docs/ui-standards.md`.

Post the sample alert:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -InFile .\samples\azure-monitor-vmss-high-cpu.json `
  -Uri http://127.0.0.1:8000/alerts/azure-monitor
```

Approve an incident:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"approver":"operator@example.com","comment":"Approved from local test"}' `
  -Uri http://127.0.0.1:8000/incidents/<incident-id>/approve
```

## Enterprise Azure Integration

For real Azure estates, connect existing alerts in two ways:

1. Configure an Azure Monitor Action Group webhook that posts common alert schema payloads to `/alerts/azure-monitor`.
2. Configure Log Analytics pull mode and call `/integrations/log-analytics/poll-alerts` on a schedule.

For one workspace per subscription, use a mapping:

```env
AIOPS_AZURE_SUBSCRIPTION_IDS=sub-a,sub-b
AIOPS_LOG_ANALYTICS_WORKSPACE_MAP=sub-a=workspace-a,sub-b=workspace-b
```

You can also use JSON:

```env
AIOPS_LOG_ANALYTICS_WORKSPACE_MAP={"sub-a":"workspace-a","sub-b":"workspace-b"}
```

`AIOPS_LOG_ANALYTICS_WORKSPACE_ID` remains available as a default fallback workspace.

Discover existing infrastructure across subscriptions:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"limit":50}' `
  -Uri http://127.0.0.1:8000/integrations/resource-graph/discover
```

Run KQL against a workspace:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"sub-a","query":"AzureActivity | take 10"}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/query
```

List all specification modules exposed by the app:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri http://127.0.0.1:8000/api/modules
```

Run a module action (example: Change Investigation Agent):

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"arguments":{"hours":24,"limit":20}}' `
  -Uri http://127.0.0.1:8000/api/modules/change_investigation_agent/run
```

Analyze KQL rows with Azure OpenAI:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"query":"AzureActivity | where TimeGenerated > ago(1h) | take 20","max_rows":20}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/analyze
```

Poll a subscription workspace for alert-like signals:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"sub-a","max_alerts":25}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/poll-alerts
```

Set `AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true` only after authenticating with Azure CLI locally or assigning managed identity/RBAC in Azure.

## State Backend

JSON remains the default backend for local development. For enterprise persistence, switch to PostgreSQL:

```env
AIOPS_STATE_BACKEND=postgres
AIOPS_POSTGRES_DSN=postgresql://<user>:<password>@<host>:5432/<database>
AIOPS_POSTGRES_SCHEMA=aiops
```

The state schema SQL bootstrap is available at `infra/sql/001_state_store.sql`.
When PostgreSQL backend is enabled, `/api/chat` also persists user/session records in `users` and `chat_sessions`.

## Safety Model

The default execution mode is `mock`, so remediation calls are simulated. Set `AIOPS_EXECUTION_MODE=live` only after configuring managed identity/RBAC and reviewing `docs/remediation-catalog.md`.

Actions must be approved, allowlisted, and non-destructive before they execute.

## Tests

```powershell
pytest
```

## Azure Deployment

The infrastructure scaffold is in `infra/main.bicep`.

```powershell
az deployment group create `
  --resource-group <rg> `
  --template-file infra/main.bicep `
  --parameters containerImage=<registry>/aiops-agent:latest
```
