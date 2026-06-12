from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request, status
from starlette.middleware.sessions import SessionMiddleware

from aiops_agent.config import Settings
from aiops_agent.models import AuthStatus, UserProfile

SESSION_USER_KEY = "user"
SESSION_TOKEN_KEY = "token"
SESSION_OBO_TOKENS_KEY = "obo_tokens"


def configure_auth(app, settings: Settings) -> OAuth:
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.auth_session_secret,
        same_site="lax",
        https_only=False,
    )

    oauth = OAuth()
    if settings.auth_enabled and settings.auth_client_id and settings.auth_client_secret:
        oauth.register(
            name="microsoft",
            client_id=settings.auth_client_id,
            client_secret=settings.auth_client_secret,
            server_metadata_url=settings.auth_metadata_url,
            client_kwargs={"scope": settings.auth_scopes},
        )
    app.state.oauth = oauth
    return oauth


def auth_status(settings: Settings) -> AuthStatus:
    return AuthStatus(
        enabled=settings.auth_enabled,
        configured=settings.auth_configured,
        authority=settings.auth_authority,
        login_url="/auth/login",
        logout_url="/auth/logout",
        profile_url="/me",
    )


def require_user(request: Request, settings: Settings) -> UserProfile:
    if not settings.auth_enabled:
        return UserProfile(
            authenticated=False,
            name="Local operator",
            username="local",
            email=None,
            claims={"auth_mode": "disabled"},
        )

    user = request.session.get(SESSION_USER_KEY)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Microsoft login required. Visit /auth/login first.",
        )
    return UserProfile.model_validate(user)


def session_user(request: Request) -> UserProfile | None:
    user = request.session.get(SESSION_USER_KEY)
    return UserProfile.model_validate(user) if user else None


def store_session_token(request: Request, token: dict[str, Any]) -> None:
    request.session[SESSION_TOKEN_KEY] = {
        "access_token": token.get("access_token"),
        "refresh_token": token.get("refresh_token"),
        "expires_at": token.get("expires_at"),
        "token_type": token.get("token_type"),
        "scope": token.get("scope"),
    }


def get_obo_access_token(request: Request, settings: Settings, scope: str) -> str | None:
    if not settings.auth_enabled or not settings.auth_enable_obo:
        return None
    if not settings.auth_client_id or not settings.auth_client_secret:
        return None

    session_token = request.session.get(SESSION_TOKEN_KEY) or {}
    user_assertion = str(session_token.get("access_token") or "").strip()
    if not user_assertion:
        return None

    now = datetime.now(timezone.utc)
    cached_tokens = request.session.get(SESSION_OBO_TOKENS_KEY) or {}
    cached_entry = cached_tokens.get(scope)
    if isinstance(cached_entry, dict):
        access_token = str(cached_entry.get("access_token") or "").strip()
        expires_at_raw = cached_entry.get("expires_at")
        if access_token and isinstance(expires_at_raw, (int, float)):
            if datetime.fromtimestamp(expires_at_raw, tz=timezone.utc) > now + timedelta(minutes=2):
                return access_token

    token_url = f"{settings.auth_authority}/oauth2/v2.0/token"
    payload = {
        "client_id": settings.auth_client_id,
        "client_secret": settings.auth_client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "requested_token_use": "on_behalf_of",
        "assertion": user_assertion,
        "scope": scope,
    }
    response = httpx.post(token_url, data=payload, timeout=30)
    response.raise_for_status()
    body = response.json()
    access_token = str(body.get("access_token") or "").strip()
    expires_in = int(body.get("expires_in") or 3600)
    if not access_token:
        return None

    cached_tokens[scope] = {
        "access_token": access_token,
        "expires_at": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    request.session[SESSION_OBO_TOKENS_KEY] = cached_tokens
    return access_token


def build_user_profile(claims: dict[str, Any]) -> UserProfile:
    return UserProfile(
        authenticated=True,
        name=claims.get("name"),
        username=claims.get("preferred_username") or claims.get("upn"),
        email=claims.get("email") or claims.get("preferred_username"),
        object_id=claims.get("oid") or claims.get("sub"),
        tenant_id=claims.get("tid"),
        claims=claims,
    )


def microsoft_logout_url(settings: Settings) -> str:
    query = urlencode({"post_logout_redirect_uri": settings.auth_post_logout_redirect_uri})
    return f"{settings.auth_authority}/oauth2/v2.0/logout?{query}"
