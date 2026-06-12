# Enterprise Azure Integration

## Integration Modes

Use both push and pull in enterprise environments:

- Push: Azure Monitor Action Groups send common alert schema webhooks to `/alerts/azure-monitor`.
- Pull: the agent queries Log Analytics with KQL through `/integrations/log-analytics/query` and can synthesize incidents from `/integrations/log-analytics/poll-alerts`.
- Discovery: the agent queries Azure Resource Graph through `/integrations/resource-graph/discover` to inventory existing VM, VMSS, and AKS resources across configured subscriptions.

## Existing Infrastructure Onboarding

1. Assign the agent managed identity read access to the existing subscriptions or management-group scoped resource groups.
2. Option A: add `AIOPS_AZURE_SUBSCRIPTION_IDS` with comma-separated subscription IDs.
3. Option B: leave `AIOPS_AZURE_SUBSCRIPTION_IDS` empty and allow subscription auto-discovery from the current Azure identity.
4. Add `AIOPS_LOG_ANALYTICS_WORKSPACE_MAP` for one workspace per subscription, or `AIOPS_LOG_ANALYTICS_WORKSPACE_ID` for a central/default workspace.
5. Keep `AIOPS_EXECUTION_MODE=mock` until approvals, RBAC, and runbooks have been validated.
6. Enable `AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true` to allow live Resource Graph and Log Analytics reads.

List the subscriptions the app can see:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri http://127.0.0.1:8000/integrations/azure/subscriptions
```

When live mode is enabled and no subscription list is configured, `/integrations/resource-graph/discover`,
cost analysis, and security findings use the discovered subscription set automatically.

For Log Analytics query/poll, if no workspace id/map is configured, the app can auto-select a workspace
for a subscription when one is discoverable.

Example `.env` for separate workspaces:

```env
AIOPS_AZURE_SUBSCRIPTION_IDS=00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002
AIOPS_LOG_ANALYTICS_WORKSPACE_MAP=00000000-0000-0000-0000-000000000001=11111111-1111-1111-1111-111111111111,00000000-0000-0000-0000-000000000002=22222222-2222-2222-2222-222222222222
```

The same mapping can be provided as JSON if that is easier for deployment pipelines:

```env
AIOPS_LOG_ANALYTICS_WORKSPACE_MAP={"00000000-0000-0000-0000-000000000001":"11111111-1111-1111-1111-111111111111","00000000-0000-0000-0000-000000000002":"22222222-2222-2222-2222-222222222222"}
```

## Azure Monitor Action Group

Create or update an existing Action Group and add a webhook receiver:

- URI: `https://<agent-host>/alerts/azure-monitor`
- Common alert schema: enabled
- Authentication: place the agent behind API Management, Container Apps auth, private ingress, or a signed gateway pattern for production.

This is the preferred path for alert ingestion because Azure Monitor sends the alert immediately and preserves alert metadata.

## Log Analytics Pull

Use pull mode when alerts are represented as KQL signals, when historical replay is needed, or while onboarding existing workspaces. The default query detects:

- Failed AzureActivity records.
- Windows error/warning events.
- Perf CPU samples above 90 percent.
- AzureMetrics records for common CPU, capacity, traffic, and availability signals.

Enterprise teams should replace the default query with workspace-specific KQL for VM, VMSS, AKS, Application Insights, Sentinel, and platform logs.

Test one mapped subscription:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"00000000-0000-0000-0000-000000000001","query":"AzureActivity | take 10"}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/query
```

Poll one mapped subscription for alert-like signals:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subscription_id":"00000000-0000-0000-0000-000000000001","max_alerts":25}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/poll-alerts
```

To raise incidents from a custom KQL query, the result must project:

- `TimeGenerated`
- `Severity`
- `RuleName`
- `ResourceId`
- `Description`

Use `samples/kql/azuremetrics-firewall-incident-signals.kql` as a starting point for Azure Firewall metric breaches. The analysis query in `samples/kql/azuremetrics-operational-summary.kql` is intentionally informational and should not be used directly for incident creation.

For a synthetic incident test, use `samples/kql/fake-firewall-incident.kql` or paste `samples/requests/log-analytics-poll-fake-firewall-incident.json` into `/integrations/log-analytics/poll-alerts`.

## Resource Graph Discovery

The discovery endpoint starts with:

- `microsoft.compute/virtualmachines`
- `microsoft.compute/virtualmachinescalesets`
- `microsoft.containerservice/managedclusters`

Pass additional resource types for App Service, databases, networking, or storage as the estate expands.

## Recommended RBAC

Read-only onboarding:

- Reader on target subscriptions/resource groups.
- Log Analytics Reader on the workspace.
- Microsoft Sentinel Reader where security enrichment is enabled.

Live remediation:

- Add narrowly scoped Compute, Monitor, and Automation permissions only for approved action types.
- Prefer runbook-specific permissions over broad Contributor.
