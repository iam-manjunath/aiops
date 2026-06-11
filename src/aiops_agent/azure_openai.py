import json
from typing import Any

from aiops_agent.config import Settings
from aiops_agent.models import (
    AzureOpenAIStatus,
    AzureOpenAITestResponse,
    LogAnalyticsAnalyzeResponse,
    LogAnalyticsQueryResponse,
)


class AzureOpenAIService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def status(self) -> AzureOpenAIStatus:
        endpoint_configured = bool(self.settings.azure_openai_endpoint)
        deployment_configured = bool(self.settings.azure_openai_deployment)
        api_key_configured = bool(self.settings.azure_openai_api_key)
        configured = self.settings.azure_openai_configured

        message = "Azure OpenAI is configured."
        if not endpoint_configured:
            message = "Set AIOPS_AZURE_OPENAI_ENDPOINT."
        elif not deployment_configured:
            message = "Set AIOPS_AZURE_OPENAI_DEPLOYMENT to your Azure deployment name."
        elif self.settings.azure_openai_auth_mode == "api_key" and not api_key_configured:
            message = "Set AIOPS_AZURE_OPENAI_API_KEY or use managed_identity auth mode."

        return AzureOpenAIStatus(
            enabled=configured,
            configured=configured,
            endpoint_configured=endpoint_configured,
            deployment_configured=deployment_configured,
            api_version=self.settings.azure_openai_api_version,
            auth_mode=self.settings.azure_openai_auth_mode,
            api_key_configured=api_key_configured,
            deployment=self.settings.azure_openai_deployment,
            message=message,
        )

    def client(self):
        if not self.settings.azure_openai_configured:
            raise ValueError(self.status().message)

        if self.settings.azure_openai_api_version.lower() == "v1":
            return self._v1_client()

        from openai import AzureOpenAI

        client_kwargs: dict[str, Any] = {
            "azure_endpoint": self.settings.azure_openai_endpoint,
            "api_version": self.settings.azure_openai_api_version,
        }

        if self.settings.azure_openai_auth_mode == "api_key":
            client_kwargs["api_key"] = self.settings.azure_openai_api_key
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default",
            )
            client_kwargs["azure_ad_token_provider"] = token_provider

        return AzureOpenAI(**client_kwargs)

    def _v1_client(self):
        from openai import OpenAI

        endpoint = (self.settings.azure_openai_endpoint or "").rstrip("/")
        client_kwargs: dict[str, Any] = {
            "base_url": f"{endpoint}/openai/v1/",
        }

        if self.settings.azure_openai_auth_mode == "api_key":
            client_kwargs["api_key"] = self.settings.azure_openai_api_key
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default",
            )
            client_kwargs["api_key"] = token_provider

        return OpenAI(**client_kwargs)

    def test_chat(self, prompt: str) -> AzureOpenAITestResponse:
        status = self.status()
        if not status.configured:
            return AzureOpenAITestResponse(
                status="not_configured",
                provider="azure_openai",
                deployment=status.deployment,
                message=status.message,
            )

        try:
            output = self._complete_text(
                system_prompt="You are a connectivity test for an Azure AIOps agent.",
                user_prompt=prompt,
                max_output_tokens=200,
            )
            return AzureOpenAITestResponse(
                status="ok",
                provider="azure_openai",
                deployment=self.settings.azure_openai_deployment,
                output=output or "Azure OpenAI returned an empty response.",
            )
        except Exception as exc:
            return AzureOpenAITestResponse(
                status="error",
                provider="azure_openai",
                deployment=self.settings.azure_openai_deployment,
                message=str(exc),
            )

    def analyze_log_rows(
        self,
        query_result: LogAnalyticsQueryResponse,
        prompt: str,
        max_rows: int,
    ) -> LogAnalyticsAnalyzeResponse:
        rows = query_result.rows[:max_rows]
        if query_result.status not in {"ok", "partial"}:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="skipped",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=query_result.message or "Log Analytics query did not return analyzable rows.",
            )
        if not rows:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="no_rows",
                workspace_id=query_result.workspace_id,
                row_count=0,
                columns=query_result.columns,
                message="Log Analytics query returned no rows.",
            )

        status = self.status()
        if not status.configured:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="not_configured",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=status.message,
            )

        try:
            analysis = self._complete_text(
                system_prompt=(
                    "You are an Azure AIOps analyst. Summarize Log Analytics rows in concise "
                    "operator language. Identify likely operational causes, call out risk, and "
                    "recommend approval-gated next steps. Do not invent facts not present in "
                    "the rows."
                ),
                user_prompt=json.dumps(
                    {
                        "instruction": prompt,
                        "columns": query_result.columns,
                        "rows": rows,
                    },
                    default=str,
                ),
                max_output_tokens=2000,
            )
            if not analysis.strip():
                return LogAnalyticsAnalyzeResponse(
                    query_status=query_result.status,
                    analysis_status="empty",
                    workspace_id=query_result.workspace_id,
                    row_count=len(query_result.rows),
                    columns=query_result.columns,
                    message=(
                        "Azure OpenAI returned no analysis text. Try a smaller max_rows value, "
                        "a more focused KQL query, or a model/deployment with sufficient output "
                        "token capacity."
                    ),
                )
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="ok",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                analysis=analysis,
            )
        except Exception as exc:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="error",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=str(exc),
            )

    def complete_text(
        self,
        system_prompt: str,
        user_prompt: str,
        max_output_tokens: int = 1200,
    ) -> str:
        status = self.status()
        if not status.configured:
            raise ValueError(status.message)
        return self._complete_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_output_tokens=max_output_tokens,
        )

    def _complete_text(
        self,
        system_prompt: str,
        user_prompt: str,
        max_output_tokens: int,
    ) -> str:
        client = self.client()
        errors: list[str] = []

        if self.settings.azure_openai_api_version.lower() == "v1" and hasattr(client, "responses"):
            try:
                response = client.responses.create(
                    model=self.settings.azure_openai_deployment,
                    instructions=system_prompt,
                    input=user_prompt,
                    max_output_tokens=max_output_tokens,
                )
                output = _extract_response_text(response)
                if output:
                    return output
            except Exception as exc:
                errors.append(f"Responses API failed: {exc}")

        try:
            response = client.chat.completions.create(
                model=self.settings.azure_openai_deployment,
                max_completion_tokens=max_output_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return _extract_response_text(response)
        except Exception as exc:
            if errors:
                raise RuntimeError("; ".join([*errors, f"Chat completions failed: {exc}"])) from exc
            raise


def _extract_response_text(response: Any) -> str:
    output_text = _read_value(response, "output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    choices = _read_value(response, "choices")
    if choices:
        choice = choices[0]
        message = _read_value(choice, "message")
        content = _read_value(message, "content") if message is not None else None
        text = _content_to_text(content)
        if text.strip():
            return text.strip()

        text = _content_to_text(_read_value(choice, "text"))
        if text.strip():
            return text.strip()

    text = _content_to_text(_read_value(response, "output"))
    return text.strip()


def _read_value(value: Any, key: str) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, dict):
            text = text.get("value")
        if isinstance(text, str):
            return text
        return " ".join(
            part
            for key in ("output_text", "content", "message")
            if (part := _content_to_text(content.get(key)))
        )
    if isinstance(content, list | tuple):
        return " ".join(part for item in content if (part := _content_to_text(item)))

    for attr in ("text", "content", "message", "output_text"):
        text = _content_to_text(getattr(content, attr, None))
        if text:
            return text
    return ""
