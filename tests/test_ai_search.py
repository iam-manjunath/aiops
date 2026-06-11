from aiops_agent.ai_search import AzureAISearchService, classify_knowledge_document
from aiops_agent.azure_openai import AzureOpenAIService
from aiops_agent.config import Settings


def test_ai_search_status_requires_endpoint_index_and_auth(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        ai_search_endpoint=None,
        ai_search_index=None,
        ai_search_api_key=None,
    )
    service = AzureAISearchService(settings, AzureOpenAIService(settings))

    status = service.status()

    assert status.configured is False
    assert "AIOPS_AI_SEARCH_ENDPOINT" in status.message


def test_ai_search_ingest_returns_configuration_only_when_live_disabled(tmp_path):
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "hana-runbook.md").write_text("# HANA recovery\nStep 1", encoding="utf-8")

    settings = Settings(
        state_file=tmp_path / "state.json",
        ai_search_endpoint="https://example.search.windows.net",
        ai_search_index="runbooks",
        ai_search_api_key="test-key",
        enable_live_azure_integrations=False,
        knowledge_source_paths=str(docs_dir),
    )
    service = AzureAISearchService(settings, AzureOpenAIService(settings))

    response = service.ingest_local_knowledge()

    assert response.status == "configuration_only"
    assert response.document_count == 1
    assert response.index == "runbooks"


def test_ai_search_query_returns_configuration_only_when_live_disabled(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        ai_search_endpoint="https://example.search.windows.net",
        ai_search_index="runbooks",
        ai_search_api_key="test-key",
        enable_live_azure_integrations=False,
    )
    service = AzureAISearchService(settings, AzureOpenAIService(settings))

    response = service.query_knowledge("How do I recover SAP HANA?")

    assert response.status == "configuration_only"
    assert response.query == "How do I recover SAP HANA?"


def test_classify_knowledge_document_variants():
    assert classify_knowledge_document("sap-hana-runbook.md") == "runbook"
    assert classify_knowledge_document("db-sop.txt") == "sop"
    assert classify_knowledge_document("incident-rca.md") == "incident"
    assert classify_knowledge_document("notes.md") == "document"
