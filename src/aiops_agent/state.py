import json
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from pydantic import BaseModel, Field

from aiops_agent.config import Settings
from aiops_agent.models import AuditEvent, Incident, RemediationAction, utcnow


class StateStore(Protocol):
    def list_incidents(self) -> list[Incident]: ...
    def get_incident(self, incident_id: str) -> Incident | None: ...
    def upsert_incident(self, incident: Incident) -> Incident: ...
    def list_actions_for_incident(self, incident_id: str) -> list[RemediationAction]: ...
    def get_action(self, action_id: str) -> RemediationAction | None: ...
    def upsert_action(self, action: RemediationAction) -> RemediationAction: ...
    def add_audit_event(self, event: AuditEvent) -> AuditEvent: ...
    def list_audit_events(self, incident_id: str | None = None) -> list[AuditEvent]: ...


class StateSnapshot(BaseModel):
    incidents: dict[str, Incident] = Field(default_factory=dict)
    actions: dict[str, RemediationAction] = Field(default_factory=dict)
    audit_events: dict[str, AuditEvent] = Field(default_factory=dict)


class JsonStateStore:
    """Small durable store for local development."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = RLock()
        self._state = self._load()

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            return sorted(self._state.incidents.values(), key=lambda item: item.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._state.incidents.get(incident_id)

    def upsert_incident(self, incident: Incident) -> Incident:
        with self._lock:
            incident.updated_at = utcnow()
            self._state.incidents[incident.id] = incident
            self._save()
            return incident

    def list_actions_for_incident(self, incident_id: str) -> list[RemediationAction]:
        with self._lock:
            return [action for action in self._state.actions.values() if action.incident_id == incident_id]

    def get_action(self, action_id: str) -> RemediationAction | None:
        with self._lock:
            return self._state.actions.get(action_id)

    def upsert_action(self, action: RemediationAction) -> RemediationAction:
        with self._lock:
            self._state.actions[action.id] = action
            self._save()
            return action

    def add_audit_event(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._state.audit_events[event.id] = event
            self._save()
            return event

    def list_audit_events(self, incident_id: str | None = None) -> list[AuditEvent]:
        with self._lock:
            events = self._state.audit_events.values()
            if incident_id:
                events = [event for event in events if event.incident_id == incident_id]
            return sorted(events, key=lambda item: item.created_at)

    def _load(self) -> StateSnapshot:
        if not self.path.exists():
            return StateSnapshot()
        with self.path.open("r", encoding="utf-8") as handle:
            return StateSnapshot.model_validate(json.load(handle))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(self._state.model_dump(mode="json"), handle, indent=2)


class PostgresStateStore:
    """PostgreSQL-backed state store for enterprise deployments."""

    def __init__(self, dsn: str, schema: str = "aiops"):
        if not dsn:
            raise ValueError("AIOPS_POSTGRES_DSN must be set for postgres backend.")
        self.dsn = dsn
        self.schema = schema
        self._lock = RLock()
        self._ensure_schema()

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg is required for postgres backend. Install project dependencies with "
                "`pip install -e \".[dev]\"`."
            ) from exc
        return psycopg.connect(self.dsn)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS "{self.schema}".incidents (
                        id TEXT PRIMARY KEY,
                        payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS "{self.schema}".actions (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        payload JSONB NOT NULL,
                        proposed_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS "{self.schema}".audit_events (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NULL,
                        action_id TEXT NULL,
                        payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_actions_incident
                    ON "{self.schema}".actions (incident_id)
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_audit_incident
                    ON "{self.schema}".audit_events (incident_id)
                    """
                )
            conn.commit()

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f'SELECT payload FROM "{self.schema}".incidents ORDER BY created_at DESC'
                    )
                    rows = cur.fetchall()
            return [Incident.model_validate(_read_payload(row[0])) for row in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f'SELECT payload FROM "{self.schema}".incidents WHERE id = %s',
                        (incident_id,),
                    )
                    row = cur.fetchone()
            if not row:
                return None
            return Incident.model_validate(_read_payload(row[0]))

    def upsert_incident(self, incident: Incident) -> Incident:
        with self._lock:
            incident.updated_at = utcnow()
            payload = incident.model_dump(mode="json")
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO "{self.schema}".incidents (id, payload, created_at, updated_at)
                        VALUES (%s, %s::jsonb, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (
                            incident.id,
                            json.dumps(payload),
                            incident.created_at,
                            incident.updated_at,
                        ),
                    )
                conn.commit()
            return incident

    def list_actions_for_incident(self, incident_id: str) -> list[RemediationAction]:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT payload
                        FROM "{self.schema}".actions
                        WHERE incident_id = %s
                        ORDER BY proposed_at ASC
                        """,
                        (incident_id,),
                    )
                    rows = cur.fetchall()
            return [RemediationAction.model_validate(_read_payload(row[0])) for row in rows]

    def get_action(self, action_id: str) -> RemediationAction | None:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f'SELECT payload FROM "{self.schema}".actions WHERE id = %s',
                        (action_id,),
                    )
                    row = cur.fetchone()
            if not row:
                return None
            return RemediationAction.model_validate(_read_payload(row[0]))

    def upsert_action(self, action: RemediationAction) -> RemediationAction:
        with self._lock:
            payload = action.model_dump(mode="json")
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO "{self.schema}".actions (
                            id, incident_id, payload, proposed_at, updated_at
                        )
                        VALUES (%s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            incident_id = EXCLUDED.incident_id,
                            payload = EXCLUDED.payload,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (
                            action.id,
                            action.incident_id,
                            json.dumps(payload),
                            action.proposed_at,
                            utcnow(),
                        ),
                    )
                conn.commit()
            return action

    def add_audit_event(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            payload = event.model_dump(mode="json")
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO "{self.schema}".audit_events (
                            id, incident_id, action_id, payload, created_at
                        )
                        VALUES (%s, %s, %s, %s::jsonb, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            payload = EXCLUDED.payload
                        """,
                        (
                            event.id,
                            event.incident_id,
                            event.action_id,
                            json.dumps(payload),
                            event.created_at,
                        ),
                    )
                conn.commit()
            return event

    def list_audit_events(self, incident_id: str | None = None) -> list[AuditEvent]:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    if incident_id:
                        cur.execute(
                            f"""
                            SELECT payload
                            FROM "{self.schema}".audit_events
                            WHERE incident_id = %s
                            ORDER BY created_at ASC
                            """,
                            (incident_id,),
                        )
                    else:
                        cur.execute(
                            f"""
                            SELECT payload
                            FROM "{self.schema}".audit_events
                            ORDER BY created_at ASC
                            """
                        )
                    rows = cur.fetchall()
            return [AuditEvent.model_validate(_read_payload(row[0])) for row in rows]


def create_state_store(settings: Settings) -> StateStore:
    if settings.state_backend == "postgres":
        if not settings.postgres_dsn:
            raise ValueError("AIOPS_POSTGRES_DSN is required when AIOPS_STATE_BACKEND=postgres.")
        return PostgresStateStore(dsn=settings.postgres_dsn, schema=settings.postgres_schema)
    return JsonStateStore(settings.state_file)


def _read_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    if isinstance(value, (bytes, bytearray)):
        return json.loads(value.decode("utf-8"))
    raise TypeError(f"Unsupported payload type: {type(value)}")
