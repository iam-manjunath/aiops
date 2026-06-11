# Python Environment Setup

This project is a Python/FastAPI application. The Dockerfile is only a packaging option; local development and office-laptop testing can run entirely from a Python virtual environment.

## Personal Laptop Build

Use this mode when you are preparing the solution without access to enterprise Azure resources:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
copy .env.example .env
python -m pytest
python -m uvicorn aiops_agent.app:create_app --factory --host 127.0.0.1 --port 8000
```

Keep these settings while working locally:

```env
AIOPS_STATE_BACKEND=json
AIOPS_EXECUTION_MODE=mock
AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=false
```

For enterprise persistence on PostgreSQL, use:

```env
AIOPS_STATE_BACKEND=postgres
AIOPS_POSTGRES_DSN=postgresql://<user>:<password>@<host>:5432/<database>
AIOPS_POSTGRES_SCHEMA=aiops
```

Schema bootstrap SQL: `infra/sql/001_state_store.sql`.

For Azure AI Search knowledge ingestion/query, set:

```env
AIOPS_AI_SEARCH_ENDPOINT=https://<search-service>.search.windows.net
AIOPS_AI_SEARCH_INDEX=aiops-knowledge
AIOPS_AI_SEARCH_API_KEY=<search-key>
AIOPS_AI_SEARCH_AUTH_MODE=api_key
AIOPS_KNOWLEDGE_SOURCE_PATHS=docs
AIOPS_KNOWLEDGE_FILE_EXTENSIONS=.md,.txt,.rst
AIOPS_KNOWLEDGE_MAX_FILE_SIZE_KB=512
```

## Office Laptop Test

On the office laptop, update `.env` with the real subscription and workspace mapping:

```env
AIOPS_AZURE_SUBSCRIPTION_IDS=<sub-a>,<sub-b>
AIOPS_LOG_ANALYTICS_WORKSPACE_MAP=<sub-a>=<workspace-id-a>,<sub-b>=<workspace-id-b>
AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true
AIOPS_EXECUTION_MODE=mock
```

Authenticate before running live read tests:

```powershell
az login
az account set --subscription <sub-a>
python -m uvicorn aiops_agent.app:create_app --factory --host 127.0.0.1 --port 8000
```

Smoke-test the API:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/
Invoke-RestMethod -Uri http://127.0.0.1:8000/integrations/status
```

Test mapped Log Analytics access:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"<sub-a>","query":"AzureActivity | take 10"}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/query
```

Test alert polling without enabling remediation:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"<sub-a>","max_alerts":25}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/poll-alerts
```

Leave `AIOPS_EXECUTION_MODE=mock` until remediation RBAC, approvals, and runbooks are reviewed.
