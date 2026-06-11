import pytest

from aiops_agent.config import Settings
from aiops_agent.state import JsonStateStore, PostgresStateStore, create_state_store


def test_create_state_store_defaults_to_json(tmp_path):
    settings = Settings(state_file=tmp_path / "state.json", state_backend="json")

    store = create_state_store(settings)

    assert isinstance(store, JsonStateStore)


def test_create_state_store_postgres_requires_dsn(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        state_backend="postgres",
        postgres_dsn=None,
    )

    with pytest.raises(ValueError, match="AIOPS_POSTGRES_DSN"):
        create_state_store(settings)


def test_create_state_store_postgres_selected(tmp_path, monkeypatch):
    settings = Settings(
        state_file=tmp_path / "state.json",
        state_backend="postgres",
        postgres_dsn="postgresql://user:pass@localhost:5432/aiops",
        postgres_schema="aiops_test",
    )
    monkeypatch.setattr(PostgresStateStore, "_ensure_schema", lambda self: None)

    store = create_state_store(settings)

    assert isinstance(store, PostgresStateStore)
