# Azure AI Search RAG

The project now supports Azure AI Search ingestion and retrieval for runbooks/SOPs, with optional Azure OpenAI summarization on top of search hits.

## Configuration

Add these values to `.env`:

```env
AIOPS_AI_SEARCH_ENDPOINT=https://<search-service>.search.windows.net
AIOPS_AI_SEARCH_INDEX=aiops-knowledge
AIOPS_AI_SEARCH_API_KEY=<search-admin-or-write-key>
AIOPS_AI_SEARCH_AUTH_MODE=api_key
AIOPS_KNOWLEDGE_SOURCE_PATHS=docs,samples
AIOPS_KNOWLEDGE_FILE_EXTENSIONS=.md,.txt,.rst
AIOPS_KNOWLEDGE_MAX_FILE_SIZE_KB=512
```

For managed identity, set:

```env
AIOPS_AI_SEARCH_AUTH_MODE=managed_identity
```

## Endpoints

- `GET /integrations/ai-search/status`
- `POST /integrations/knowledge/ingest`
- `POST /integrations/knowledge/query`

## Tool Execution

The same capability is available from `POST /api/tools/execute`:

- `ingest_knowledge_base`
- `query_knowledge_base`

## Sample Ingestion Request

```json
{
  "source_paths": ["docs"],
  "max_files": 200,
  "force_reindex": false
}
```

Saved copy: `samples/requests/knowledge-ingest.json`.

## Sample Query Request

```json
{
  "query": "How do I recover SAP HANA?",
  "top": 5,
  "use_ai_summary": true
}
```

Saved copy: `samples/requests/knowledge-query.json`.

## Runtime Modes

- If search is not configured, responses return `status=not_configured`.
- If live integrations are disabled, responses return `status=configuration_only`.
- With live integrations enabled, documents are indexed and queried from Azure AI Search.
