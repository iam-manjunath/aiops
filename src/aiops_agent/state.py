import json
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, Field

from aiops_agent.config import Settings
from aiops_agent.models import AuditEvent, Incident, RemediationAction, UserProfile, utcnow


class StateStore(Protocol):
    def list_incidents(self) -> list[Incident]: ...
    def get_incident(self, incident_id: str) -> Incident | None: ...
    def upsert_incident(self, incident: Incident) -> Incident: ...
    def list_actions_for_incident(self, incident_id: str) -> list[RemediationAction]: ...
    def get_action(self, action_id: str) -> RemediationAction | None: ...
    def upsert_action(self, action: RemediationAction) -> RemediationAction: ...
    def add_audit_event(self, event: AuditEvent) -> AuditEvent: ...
    def list_audit_events(self, incident_id: str | None = None) -> list[AuditEvent]: ...
    def upsert_user(self, user: UserProfile, role: str = "Operator") -> str: ...
    def record_chat_exchange(
        self,
        session_id: str | None,
        user: UserProfile,
        user_message: str,
        assistant_message: str,
        metadata: dict[str, Any] | None = None,
    ) -> str: ...
    def get_chat_session(self, session_id: str) -> dict[str, Any] | None: ...


class StoredUserRecord(BaseModel):
    id: str
    identity_key: str
    username: str | None = None
    email: str | None = None
    role: str = "Operator"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ChatSessionRecord(BaseModel):
    id: str
    client_session_id: str | None = None
    user_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    message_count: int = 0
    last_user_message: str | None = None
    last_assistant_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class StateSnapshot(BaseModel):
    incidents: dict[str, Incident] = Field(default_factory=dict)
    actions: dict[str, RemediationAction] = Field(default_factory=dict)
    audit_events: dict[str, AuditEvent] = Field(default_factory=dict)
    users: dict[str, StoredUserRecord] = Field(default_factory=dict)
    chat_sessions: dict[str, ChatSessionRecord] = Field(default_factory=dict)


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

    def upsert_user(self, user: UserProfile, role: str = "Operator") -> str:
        with self._lock:
            identity_key = _user_identity_key(user)
            for existing in self._state.users.values():
                if existing.identity_key == identity_key:
                    existing.username = user.username or existing.username
                    existing.email = user.email or existing.email
                    existing.role = role or existing.role
                    existing.updated_at = utcnow()
                    self._state.users[existing.id] = existing
                    self._save()
                    return existing.id

            user_id = str(uuid4())
            record = StoredUserRecord(
                id=user_id,
                identity_key=identity_key,
                username=user.username,
                email=user.email,
                role=role,
            )
            self._state.users[user_id] = record
            self._save()
            return user_id

    def record_chat_exchange(
        self,
        session_id: str | None,
        user: UserProfile,
        user_message: str,
        assistant_message: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        with self._lock:
            user_id = self.upsert_user(user)
            record = self._find_chat_session(session_id)
            if not record:
                new_session_id = str(uuid4())
                record = ChatSessionRecord(
                    id=new_session_id,
                    client_session_id=session_id,
                    user_id=user_id,
                )

            record.user_id = user_id
            record.message_count += 1
            record.last_user_message = user_message
            record.last_assistant_message = assistant_message
            record.updated_at = utcnow()
            merged_metadata = dict(record.metadata)
            if metadata:
                merged_metadata.update(metadata)
            record.metadata = merged_metadata
            self._state.chat_sessions[record.id] = record
            self._save()
            return record.id

    def get_chat_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._find_chat_session(session_id)
            return record.model_dump(mode="json") if record else None

    def _find_chat_session(self, session_id: str | None) -> ChatSessionRecord | None:
        if not session_id:
            return None
        if session_id in self._state.chat_sessions:
            return self._state.chat_sessions[session_id]
        for record in self._state.chat_sessions.values():
            if record.client_session_id == session_id:
                return record
        return None

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
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS "{self.schema}".users (
                        id UUID PRIMARY KEY,
                        identity_key VARCHAR(255) NOT NULL UNIQUE,
                        username VARCHAR(255) NULL,
                        email VARCHAR(255) NULL,
                        role VARCHAR(100) NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS "{self.schema}".chat_sessions (
                        id UUID PRIMARY KEY,
                        client_session_id VARCHAR(255) NULL UNIQUE,
                        user_id UUID NULL REFERENCES "{self.schema}".users(id),
                        created_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL,
                        message_count INTEGER NOT NULL DEFAULT 0,
                        last_user_message TEXT NULL,
                        last_assistant_message TEXT NULL,
                        metadata JSONB NOT NULL DEFAULT '{{}}'::jsonb
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_chat_sessions_user
                    ON "{self.schema}".chat_sessions (user_id)
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

    def upsert_user(self, user: UserProfile, role: str = "Operator") -> str:
        with self._lock:
            identity_key = _user_identity_key(user)
            user_id = str(uuid4())
            now = utcnow()
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO "{self.schema}".users (
                            id, identity_key, username, email, role, created_at, updated_at
                        )
                        VALUES (%s::uuid, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (identity_key) DO UPDATE SET
                            username = EXCLUDED.username,
                            email = EXCLUDED.email,
                            role = EXCLUDED.role,
                            updated_at = EXCLUDED.updated_at
                        RETURNING id::text
                        """,
                        (
                            user_id,
                            identity_key,
                            user.username,
                            user.email,
                            role,
                            now,
                            now,
                        ),
                    )
                    row = cur.fetchone()
                conn.commit()
            return row[0]

    def record_chat_exchange(
        self,
        session_id: str | None,
        user: UserProfile,
        user_message: str,
        assistant_message: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        with self._lock:
            user_id = self.upsert_user(user)
            existing = self._lookup_chat_session_id(session_id)
            now = utcnow()
            merged_metadata = dict(metadata or {})

            with self._connect() as conn:
                with conn.cursor() as cur:
                    if existing:
                        cur.execute(
                            f"""
                            UPDATE "{self.schema}".chat_sessions
                            SET
                                user_id = %s::uuid,
                                updated_at = %s,
                                message_count = message_count + 1,
                                last_user_message = %s,
                                last_assistant_message = %s,
                                metadata = COALESCE(metadata, '{{}}'::jsonb) || %s::jsonb
                            WHERE id = %s::uuid
                            RETURNING id::text
                            """,
                            (
                                user_id,
                                now,
                                user_message,
                                assistant_message,
                                json.dumps(merged_metadata),
                                existing,
                            ),
                        )
                        row = cur.fetchone()
                    else:
                        new_session_id = str(uuid4())
                        cur.execute(
                            f"""
                            INSERT INTO "{self.schema}".chat_sessions (
                                id, client_session_id, user_id, created_at, updated_at,
                                message_count, last_user_message, last_assistant_message, metadata
                            )
                            VALUES (%s::uuid, %s, %s::uuid, %s, %s, %s, %s, %s, %s::jsonb)
                            RETURNING id::text
                            """,
                            (
                                new_session_id,
                                session_id,
                                user_id,
                                now,
                                now,
                                1,
                                user_message,
                                assistant_message,
                                json.dumps(merged_metadata),
                            ),
                        )
                        row = cur.fetchone()
                conn.commit()
            return row[0]

    def get_chat_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT id::text, client_session_id, user_id::text, created_at, updated_at,
                               message_count, last_user_message, last_assistant_message, metadata
                        FROM "{self.schema}".chat_sessions
                        WHERE id::text = %s OR client_session_id = %s
                        LIMIT 1
                        """,
                        (session_id, session_id),
                    )
                    row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "client_session_id": row[1],
                "user_id": row[2],
                "created_at": row[3].isoformat() if row[3] else None,
                "updated_at": row[4].isoformat() if row[4] else None,
                "message_count": row[5],
                "last_user_message": row[6],
                "last_assistant_message": row[7],
                "metadata": _read_payload(row[8]),
            }

    def _lookup_chat_session_id(self, session_id: str | None) -> str | None:
        if not session_id:
            return None
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT id::text
                    FROM "{self.schema}".chat_sessions
                    WHERE id::text = %s OR client_session_id = %s
                    LIMIT 1
                    """,
                    (session_id, session_id),
                )
                row = cur.fetchone()
        return row[0] if row else None


def create_state_store(settings: Settings) -> StateStore:
    if settings.state_backend == "postgres":
        if not settings.postgres_dsn:
            raise ValueError("AIOPS_POSTGRES_DSN is required when AIOPS_STATE_BACKEND=postgres.")
        return PostgresStateStore(dsn=settings.postgres_dsn, schema=settings.postgres_schema)
    return JsonStateStore(settings.state_file)


def _user_identity_key(user: UserProfile) -> str:
    return (
        user.object_id
        or user.email
        or user.username
        or user.name
        or ("local-authenticated" if user.authenticated else "local-unauthenticated")
    )


def _read_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    if isinstance(value, (bytes, bytearray)):
        return json.loads(value.decode("utf-8"))
    raise TypeError(f"Unsupported payload type: {type(value)}")
