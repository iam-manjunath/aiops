# Azure Cloud Operations Copilot

## Overview

Azure Cloud Operations Copilot is an AI-powered operations assistant designed to help cloud engineers, DevOps teams, SREs, and platform administrators manage Azure infrastructure using natural language.

The system leverages Azure OpenAI, Azure Resource Graph, Azure Monitor, Azure Activity Logs, Azure AI Search, and other Azure services to provide:

* Infrastructure discovery
* Operational troubleshooting
* Incident investigation
* Cost optimization
* Security assessments
* Runbook assistance
* Automation execution

---

# Goals

Enable users to ask questions such as:

* Why is VM `sap-prd-01` down?
* Show all production VMs.
* Investigate CPU spike on VM `hana01`.
* What changed in the last 24 hours?
* Show security risks in Production.
* Find resources without backups.
* Restart VM `app01`.

And receive actionable responses with supporting evidence.

---

# High-Level Architecture

```text
Users
  |
  +-- Web Portal
  +-- Microsoft Teams
  +-- REST API

          |
          v

+--------------------------------+
| Azure Cloud Operations Copilot |
| FastAPI Backend                |
+--------------------------------+

          |
          v

+-----------------------------+
| Azure OpenAI                |
| GPT-4.1 / GPT-4o            |
+-----------------------------+

          |
          v

+-----------------------------+
| Tool Execution Layer        |
+-----------------------------+
| Resource Graph              |
| Azure Monitor               |
| Activity Logs               |
| Cost Management             |
| Defender for Cloud          |
| Azure Policy                |
| ARM APIs                    |
+-----------------------------+

          |
          v

+-----------------------------+
| Azure AI Search             |
| Knowledge Base / RAG        |
+-----------------------------+

          |
          v

+-----------------------------+
| PostgreSQL                  |
+-----------------------------+
```

---

# Technology Stack

## Frontend

### Option 1

* React
* Next.js
* Material UI

### Option 2

* Microsoft Teams App

---

## Backend

* Python 3.12+
* FastAPI
* Uvicorn

---

## AI Services

* Azure OpenAI
* GPT-4.1
* GPT-4o

---

## Database

* PostgreSQL

---

## Search

* Azure AI Search

---

## Hosting

* Azure App Service
* Azure Container Apps
* AKS (Optional)

---

# Functional Requirements

---

# Module 1: Resource Discovery Agent

## Purpose

Discover Azure resources across subscriptions.

## Example Queries

```text
Show all SAP VMs
List production resources
Show Linux VMs
Show resources without tags
```

## Azure APIs

* Azure Resource Graph
* ARM APIs

## Features

* Search by resource type
* Search by tag
* Search by subscription
* Search by resource group
* Search by owner

## Output Example

```json
{
  "resource_count": 15,
  "production": 8,
  "non_production": 7
}
```

---

# Module 2: VM Health Agent

## Purpose

Analyze VM health.

## Example Queries

```text
Why is vm-prod-01 unavailable?
Investigate VM performance.
Check VM health.
```

## Checks

* Power state
* Boot diagnostics
* CPU utilization
* Memory utilization
* Disk usage
* VM extensions
* Monitoring agent status

## APIs

* Azure Monitor
* Compute API

## Output

Root cause analysis report.

---

# Module 3: Network Troubleshooting Agent

## Purpose

Diagnose connectivity issues.

## Example Queries

```text
Why cannot I SSH?
Why is HTTPS failing?
Check connectivity.
```

## Checks

* NSG rules
* Route tables
* Load balancer health
* Public IP assignment
* DNS resolution
* Firewall rules
* Private endpoints

## APIs

* Network Management APIs

---

# Module 4: Cost Optimization Agent

## Purpose

Identify cost savings opportunities.

## Example Queries

```text
Why did costs increase?
Show expensive resources.
Find idle VMs.
```

## APIs

* Cost Management API
* Azure Advisor

## Features

* Monthly trend analysis
* Idle resource detection
* Rightsizing recommendations
* Reserved Instance recommendations

---

# Module 5: Security Agent

## Purpose

Identify security risks.

## Example Queries

```text
Show public IPs.
Find open RDP ports.
Show critical vulnerabilities.
```

## APIs

* Microsoft Defender for Cloud
* Azure Policy

## Checks

* Open management ports
* Missing backups
* Missing monitoring
* Public exposure
* Security recommendations

---

# Module 6: Change Investigation Agent

## Purpose

Identify recent changes.

## Example Queries

```text
What changed yesterday?
Who modified the NSG?
Show recent deployments.
```

## APIs

* Azure Activity Logs

## Features

* Deployment history
* RBAC changes
* Policy changes
* Resource creation
* Resource deletion

---

# Module 7: Incident RCA Agent

## Purpose

Automated incident investigation.

## Example Queries

```text
Investigate outage.
Perform root cause analysis.
```

## Inputs

* Alerts
* Metrics
* Logs
* Recent changes

## Output

```text
Incident Summary
Timeline
Impact
Root Cause
Corrective Action
Preventive Action
```

---

# Module 8: Knowledge Base Agent

## Purpose

Answer questions using internal documentation.

## Sources

* Runbooks
* SOPs
* Architecture documents
* Incident reports
* Lessons learned

## Backend

Azure AI Search + RAG

## Example Queries

```text
How do I recover SAP HANA?
How do I rotate OpenAI keys?
```

---

# Module 9: Automation Agent

## Purpose

Execute approved actions.

## Supported Actions

* Start VM
* Stop VM
* Restart VM
* Scale VM
* Create Snapshot
* Execute Runbook

## Workflow

1. Validate permissions
2. Generate impact assessment
3. Request approval
4. Execute action
5. Audit action

---

# MCP Tool Design

## Required Tools

```python
search_resources()

get_vm_health()

query_monitor_metrics()

get_activity_logs()

check_nsg_rules()

investigate_incident()

get_cost_analysis()

get_security_findings()

restart_vm()

start_vm()

stop_vm()

create_snapshot()

run_automation_runbook()
```

---

# Database Schema

## users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    role VARCHAR(100),
    created_at TIMESTAMP
);
```

## chat_sessions

```sql
CREATE TABLE chat_sessions (
    id UUID PRIMARY KEY,
    user_id UUID,
    created_at TIMESTAMP
);
```

## audit_logs

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    action VARCHAR(255),
    user_id UUID,
    status VARCHAR(50),
    timestamp TIMESTAMP
);
```

## incidents

```sql
CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    title VARCHAR(255),
    severity VARCHAR(50),
    root_cause TEXT,
    created_at TIMESTAMP
);
```

---

# Security Requirements

## Authentication

* Azure Entra ID
* OAuth2
* OIDC

## Authorization

Role-Based Access Control (RBAC)

### Roles

* Viewer
* Operator
* Administrator

---

# Logging

Store:

* User prompts
* Tool calls
* Executed actions
* Errors
* Incident investigations

---

# Non-Functional Requirements

## Availability

99.9%

## Response Time

* Basic query: < 5 seconds
* Investigation: < 60 seconds

## Scalability

Support:

* 500 concurrent users
* Multi-subscription environments

---

# API Design

## Chat Endpoint

```http
POST /api/chat
```

Request

```json
{
  "message": "Why is vm-prod-01 unavailable?"
}
```

---

## Health Endpoint

```http
GET /api/health
```

---

## Tool Execution Endpoint

```http
POST /api/tools/execute
```

---

# MVP Roadmap

## Sprint 1

* FastAPI backend
* Azure OpenAI integration
* Resource Graph integration
* VM Health Agent
* Activity Log Agent

## Sprint 2

* Azure Monitor integration
* Cost Optimization Agent
* Knowledge Base Agent

## Sprint 3

* Security Agent
* Incident RCA Agent
* Teams Integration

## Sprint 4

* Automation Agent
* Approval Workflows
* Production Hardening

---

# Future Enhancements

## Phase 2

* AKS Troubleshooting Agent
* SAP HANA Operations Agent
* Azure Landing Zone Compliance Agent
* Terraform Review Agent
* FinOps Assistant

## Phase 3

* Autonomous Incident Response
* Predictive Failure Detection
* AI Generated Runbooks
* Automated RCA Reports
* ServiceNow Integration

---

# Success Metrics

* Reduce MTTR by 50%
* Reduce manual troubleshooting effort by 40%
* Reduce cloud costs by 10%
* Improve operational visibility
* Improve incident response time

---

# Deliverables

1. FastAPI Backend
2. Azure OpenAI Integration
3. Azure Resource Graph Tooling
4. Azure Monitor Tooling
5. Azure Activity Log Tooling
6. Azure AI Search Integration
7. React Frontend
8. Teams Integration
9. PostgreSQL Database
10. CI/CD Pipeline
11. Documentation
12. Production Deployment Templates

```
```
