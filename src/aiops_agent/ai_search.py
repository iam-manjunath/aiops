from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from aiops_agent.azure_openai import AzureOpenAIService
from aiops_agent.config import Settings
from aiops_agent.models import (
    AzureAISearchStatus,
    KnowledgeIngestResponse,
    KnowledgeQueryResponse,
)


class AzureAISearchService:
    def __init__(self, settings: Settings, azure_openai: AzureOpenAIService):
        self.settings = settings
        self.azure_openai = azure_openai

    def status(self) -> AzureAISearchStatus:
        endpoint_configured = bool(self.settings.ai_search_endpoint)
        index_configured = bool(self.settings.ai_search_index)
        api_key_configured = bool(self.settings.ai_search_api_key)
        configured = self.settings.ai_search_configured

        message = "Azure AI Search is configured."
        if not endpoint_configured:
            message = "Set AIOPS_AI_SEARCH_ENDPOINT."
        elif not index_configured:
            message = "Set AIOPS_AI_SEARCH_INDEX."
        elif self.settings.ai_search_auth_mode == "api_key" and not api_key_configured:
            message = "Set AIOPS_AI_SEARCH_API_KEY or use managed_identity auth mode."

        return AzureAISearchStatus(
            enabled=configured,
            configured=configured,
            endpoint_configured=endpoint_configured,
            index_configured=index_configured,
            auth_mode=self.settings.ai_search_auth_mode,
            api_key_configured=api_key_configured,
            endpoint=self.settings.ai_search_endpoint,
            index=self.settings.ai_search_index,
            message=message,
        )

    def ingest_local_knowledge(
        self,
        source_paths: list[str] | None = None,
        max_files: int = 200,
        force_reindex: bool = False,
    ) -> KnowledgeIngestResponse:
        status = self.status()
        if not status.configured:
            return KnowledgeIngestResponse(
                status="not_configured",
                index=status.index,
                message=status.message,
            )

        sources = source_paths or self.settings.knowledge_source_path_list
        documents, errors = self._collect_documents(sources, max_files)
        if not documents:
            return KnowledgeIngestResponse(
                status="no_documents",
                index=status.index,
                document_count=0,
                indexed_count=0,
                failed_count=0,
                sources=sources,
                errors=errors,
                message="No eligible knowledge documents found for ingestion.",
            )

        if not self.settings.enable_live_azure_integrations:
            return KnowledgeIngestResponse(
                status="configuration_only",
                index=status.index,
                document_count=len(documents),
                indexed_count=0,
                failed_count=0,
                sources=sources,
                errors=errors,
                message="Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to ingest into Azure AI Search.",
            )

        try:
            self._ensure_index()
            search_client = self._search_client()
            indexed_count = 0
            failed: list[str] = list(errors)
            for batch in _chunks(documents, 500):
                results = search_client.merge_or_upload_documents(batch)
                for result in results:
                    if getattr(result, "succeeded", False):
                        indexed_count += 1
                    else:
                        key = getattr(result, "key", "unknown")
                        failed.append(
                            f"{key}: {getattr(result, 'error_message', 'indexing failed')}"
                        )
            return KnowledgeIngestResponse(
                status="ok" if not failed else "partial",
                index=status.index,
                document_count=len(documents),
                indexed_count=indexed_count,
                failed_count=len(failed),
                sources=sources,
                errors=failed[:20],
                message=None if not failed else "Some documents failed indexing.",
            )
        except Exception as exc:
            return KnowledgeIngestResponse(
                status="error",
                index=status.index,
                document_count=len(documents),
                indexed_count=0,
                failed_count=len(documents),
                sources=sources,
                errors=[*errors, str(exc)],
                message=f"Azure AI Search ingestion failed: {exc}",
            )

    def query_knowledge(
        self,
        query: str,
        top: int = 5,
        use_ai_summary: bool = True,
    ) -> KnowledgeQueryResponse:
        status = self.status()
        if not status.configured:
            return KnowledgeQueryResponse(
                status="not_configured",
                index=status.index,
                query=query,
                message=status.message,
            )

        if not self.settings.enable_live_azure_integrations:
            return KnowledgeQueryResponse(
                status="configuration_only",
                index=status.index,
                query=query,
                message="Set AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true to query Azure AI Search.",
            )

        try:
            search_client = self._search_client()
            results = search_client.search(
                search_text=query,
                top=max(1, min(top, 20)),
                include_total_count=True,
                select=["id", "title", "content", "source", "category", "updated_at"],
            )
            hits: list[dict[str, Any]] = []
            for item in results:
                content = str(item.get("content") or "")
                hits.append(
                    {
                        "id": item.get("id"),
                        "title": item.get("title"),
                        "source": item.get("source"),
                        "category": item.get("category"),
                        "updated_at": item.get("updated_at"),
                        "excerpt": content[:1200],
                    }
                )

            answer = None
            if use_ai_summary and hits and self.azure_openai.status().configured:
                answer = self._build_rag_answer(query, hits)

            return KnowledgeQueryResponse(
                status="ok",
                index=status.index,
                query=query,
                hit_count=len(hits),
                hits=hits,
                answer=answer,
                message=None,
            )
        except Exception as exc:
            return KnowledgeQueryResponse(
                status="error",
                index=status.index,
                query=query,
                hit_count=0,
                hits=[],
                answer=None,
                message=f"Azure AI Search query failed: {exc}",
            )

    def _build_rag_answer(self, query: str, hits: list[dict[str, Any]]) -> str:
        context_blocks = [
            {
                "source": hit.get("source"),
                "title": hit.get("title"),
                "excerpt": hit.get("excerpt"),
            }
            for hit in hits[:5]
        ]
        return self.azure_openai.complete_text(
            system_prompt=(
                "You are an Azure operations knowledge assistant. Use only the provided runbook/SOP "
                "snippets, cite source paths from the context, and do not invent steps."
            ),
            user_prompt=(
                "Question:\n"
                f"{query}\n\n"
                "Knowledge snippets:\n"
                f"{context_blocks}"
            ),
            max_output_tokens=1200,
        )

    def _collect_documents(
        self,
        source_paths: list[str],
        max_files: int,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        extensions = self.settings.knowledge_file_extension_set
        max_bytes = self.settings.knowledge_max_file_size_kb * 1024
        documents: list[dict[str, Any]] = []
        errors: list[str] = []

        for raw_source in source_paths:
            source = Path(raw_source).expanduser()
            if not source.exists():
                errors.append(f"Source path not found: {source}")
                continue
            if source.is_file():
                candidates = [source]
            else:
                candidates = [path for path in source.rglob("*") if path.is_file()]

            for candidate in candidates:
                if len(documents) >= max_files:
                    break
                if extensions and candidate.suffix.lower() not in extensions:
                    continue
                if candidate.stat().st_size > max_bytes:
                    errors.append(f"Skipped large file: {candidate}")
                    continue
                try:
                    content = candidate.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    try:
                        content = candidate.read_text(encoding="latin-1")
                    except Exception as exc:
                        errors.append(f"Failed to read {candidate}: {exc}")
                        continue
                except Exception as exc:
                    errors.append(f"Failed to read {candidate}: {exc}")
                    continue

                documents.append(
                    {
                        "id": sha256(str(candidate.resolve()).encode("utf-8")).hexdigest(),
                        "title": candidate.stem,
                        "content": content[:32000],
                        "source": str(candidate),
                        "category": classify_knowledge_document(candidate.name),
                        "updated_at": datetime.fromtimestamp(
                            candidate.stat().st_mtime, tz=UTC
                        ).isoformat(),
                    }
                )
        return documents, errors

    def _search_client(self):
        from azure.search.documents import SearchClient

        return SearchClient(
            endpoint=self.settings.ai_search_endpoint,
            index_name=self.settings.ai_search_index,
            credential=self._search_credential(),
        )

    def _search_index_client(self):
        from azure.search.documents.indexes import SearchIndexClient

        return SearchIndexClient(
            endpoint=self.settings.ai_search_endpoint,
            credential=self._search_credential(),
        )

    def _search_credential(self):
        if self.settings.ai_search_auth_mode == "api_key":
            from azure.core.credentials import AzureKeyCredential

            return AzureKeyCredential(self.settings.ai_search_api_key or "")

        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential()

    def _ensure_index(self) -> None:
        from azure.core.exceptions import ResourceNotFoundError
        from azure.search.documents.indexes.models import SearchFieldDataType
        from azure.search.documents.indexes.models import SearchIndex
        from azure.search.documents.indexes.models import SearchableField, SimpleField

        index_client = self._search_index_client()
        try:
            index_client.get_index(self.settings.ai_search_index)
            return
        except ResourceNotFoundError:
            pass

        fields = [
            SimpleField(name="id", type=SearchFieldDataType.String, key=True),
            SearchableField(name="title", type=SearchFieldDataType.String),
            SearchableField(name="content", type=SearchFieldDataType.String),
            SimpleField(name="source", type=SearchFieldDataType.String, filterable=True),
            SimpleField(name="category", type=SearchFieldDataType.String, filterable=True),
            SimpleField(name="updated_at", type=SearchFieldDataType.String, filterable=True),
        ]
        index = SearchIndex(name=self.settings.ai_search_index, fields=fields)
        index_client.create_index(index)


def classify_knowledge_document(filename: str) -> str:
    name = filename.lower()
    if "runbook" in name:
        return "runbook"
    if "sop" in name:
        return "sop"
    if "incident" in name:
        return "incident"
    return "document"


def _chunks(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
