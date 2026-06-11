import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="AIOPS_", env_file=".env", extra="ignore")

    app_name: str = "Azure AIOps Agent"
    environment: str = "local"
    state_backend: Literal["json", "postgres"] = "json"
    state_file: Path = Path(".data/aiops-state.json")
    postgres_dsn: str | None = None
    postgres_schema: str = "aiops"
    execution_mode: Literal["mock", "live"] = "mock"
    remediation_allowlist: str = (
        "restart_vm,resize_vmss,run_automation_webhook,adjust_autoscale_rule,"
        "create_ticket,manual_action_required"
    )
    destructive_action_allowlist: str = ""

    azure_subscription_ids: str = ""
    log_analytics_workspace_id: str | None = None
    log_analytics_workspace_map: str = ""
    log_query_timespan_minutes: int = 60
    enable_live_azure_integrations: bool = False
    automation_webhook_url: str | None = None

    auth_enabled: bool = False
    auth_tenant_id: str = "organizations"
    auth_client_id: str | None = None
    auth_client_secret: str | None = None
    auth_session_secret: str = "change-me-to-a-long-random-secret"
    auth_scopes: str = "openid profile email"
    auth_post_logout_redirect_uri: str = "http://127.0.0.1:8000/"

    azure_openai_endpoint: str | None = None
    azure_openai_deployment: str | None = None
    azure_openai_api_version: str = "2024-02-15-preview"
    azure_openai_api_key: str | None = None
    azure_openai_auth_mode: Literal["api_key", "managed_identity"] = "api_key"

    @field_validator("remediation_allowlist", "destructive_action_allowlist")
    @classmethod
    def normalize_csv(cls, value: str) -> str:
        return ",".join(part.strip() for part in value.split(",") if part.strip())

    @property
    def subscription_id_list(self) -> list[str]:
        return [part.strip() for part in self.azure_subscription_ids.split(",") if part.strip()]

    @property
    def workspace_map(self) -> dict[str, str]:
        if not self.log_analytics_workspace_map.strip():
            return {}

        raw_value = self.log_analytics_workspace_map.strip()
        if raw_value.startswith("{"):
            parsed = json.loads(raw_value)
            return {str(key).strip(): str(value).strip() for key, value in parsed.items() if value}

        mappings: dict[str, str] = {}
        for pair in raw_value.split(","):
            if not pair.strip():
                continue
            if "=" not in pair:
                raise ValueError(
                    "AIOPS_LOG_ANALYTICS_WORKSPACE_MAP must use 'subscription=workspace' pairs "
                    "or a JSON object."
                )
            subscription_id, workspace_id = pair.split("=", 1)
            mappings[subscription_id.strip()] = workspace_id.strip()
        return mappings

    def resolve_workspace_id(self, subscription_id: str | None = None) -> str | None:
        if subscription_id and subscription_id in self.workspace_map:
            return self.workspace_map[subscription_id]
        return self.log_analytics_workspace_id

    @property
    def remediation_allowlist_set(self) -> set[str]:
        return {part.strip() for part in self.remediation_allowlist.split(",") if part.strip()}

    @property
    def destructive_action_allowlist_set(self) -> set[str]:
        return {part.strip() for part in self.destructive_action_allowlist.split(",") if part.strip()}

    @property
    def azure_openai_enabled(self) -> bool:
        return self.azure_openai_configured

    @property
    def azure_openai_configured(self) -> bool:
        if not (self.azure_openai_endpoint and self.azure_openai_deployment):
            return False
        if self.azure_openai_auth_mode == "api_key":
            return bool(self.azure_openai_api_key)
        return True

    @property
    def auth_configured(self) -> bool:
        return bool(self.auth_enabled and self.auth_client_id and self.auth_client_secret)

    @property
    def auth_authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.auth_tenant_id}"

    @property
    def auth_metadata_url(self) -> str:
        return f"{self.auth_authority}/v2.0/.well-known/openid-configuration"


@lru_cache
def get_settings() -> Settings:
    return Settings()
