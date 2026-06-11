import pytest

from aiops_agent.config import Settings
from aiops_agent.models import UserProfile
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


def test_json_state_store_chat_session_persistence(tmp_path):
    settings = Settings(state_file=tmp_path / "state.json", state_backend="json")
    store = create_state_store(settings)
    user = UserProfile(authenticated=False, username="local", name="Local operator")

    session_id = store.record_chat_exchange(
        session_id=None,
        user=user,
        user_message="hello",
        assistant_message="world",
        metadata={"suggested_tool": "search_resources"},
    )

    assert session_id
    record = store.get_chat_session(session_id)
    assert record is not None
    assert record["message_count"] == 1
    assert record["metadata"]["suggested_tool"] == "search_resources"
