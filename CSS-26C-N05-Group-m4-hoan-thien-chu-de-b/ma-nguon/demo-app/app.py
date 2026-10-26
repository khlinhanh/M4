"""
LƯU Ý BẢO MẬT (LOCAL DEMO ONLY, NOT PRODUCTION-READY):
- Ứng dụng này sử dụng in-memory dictionary (`sessions`) để lưu session phục vụ mục đích demo và kiểm thử nội bộ.
- Trong môi trường production thực tế, cơ chế này không sẵn sàng (not production-ready).
  Bắt buộc phải thay thế bằng giải pháp lưu trữ session tập trung/phân tán an toàn (như Redis / Encrypted Cookie)
  kèm cơ chế hết hạn (TTL) và dọn dẹp phiên để tránh rò rỉ bộ nhớ và hỗ trợ mở rộng ngang (horizontal scaling).
"""
import base64
import hashlib
import html
import hmac
import os
import secrets
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jwt import PyJWKClient


app = FastAPI()

CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
APP_NAME = os.environ["APP_NAME"]
APP_PORT = int(os.environ["APP_PORT"])
OIDC_ISSUER = os.environ["OIDC_ISSUER"]
OIDC_INTERNAL_URL = os.environ.get("OIDC_INTERNAL_URL", OIDC_ISSUER)
RESOURCE_SERVER_URL = os.environ["RESOURCE_SERVER_URL"].rstrip("/")
REDIRECT_URI = f"http://localhost:{APP_PORT}/callback"
SESSION_COOKIE = f"oidc_session_{CLIENT_ID}"
# LƯU Ý BẢO MẬT: Session lưu tạm trong bộ nhớ (in-memory dict) chỉ phục vụ mục đích demo nội bộ (local demo only).
# Trong môi trường production thật, bắt buộc phải dùng kho lưu trữ phân tán an toàn (như Redis / Encrypted Cookie)
# kèm cơ chế TTL/expiration để tránh rò rỉ bộ nhớ và hỗ trợ mở rộng (scale ngang).
sessions: dict[str, dict[str, Any]] = {}
def get_oidc_config() -> dict[str, Any]:
    try:
        response = requests.get(
            f"{OIDC_INTERNAL_URL}/.well-known/openid-configuration",
            timeout=5,
        )
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not retrieve Keycloak OpenID configuration",
        ) from exc


def internalize_keycloak_url(url: str) -> str:
    return url.replace("http://localhost:8080", "http://keycloak:8080", 1)


def validate_id_token(
    id_token: str,
    nonce: str,
    jwks_uri: str,
) -> dict[str, Any]:
    try:
        signing_key = PyJWKClient(
            internalize_keycloak_url(jwks_uri)
        ).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=OIDC_ISSUER,
            options={
                "require": ["iss", "aud", "exp", "iat", "nonce"],
            },
        )
    except jwt.PyJWKClientConnectionError as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not retrieve Keycloak signing keys",
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid OIDC ID token") from exc

    if not hmac.compare_digest(claims["nonce"], nonce):
        raise HTTPException(status_code=401, detail="OIDC nonce mismatch")
    return claims


def get_session(request: Request) -> tuple[str | None, dict[str, Any] | None]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None, None
    return session_id, sessions.get(session_id)


def page(title: str, content: str) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html lang='vi'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<body style='font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem'>"
        f"<h1>{html.escape(title)}</h1>{content}</body></html>"
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    _, session = get_session(request)
    if not session or "access_token" not in session:
        return page(
            APP_NAME,
            "<p>Đăng nhập qua Keycloak bằng OpenID Connect.</p>"
            "<p><a href='/login'>Đăng nhập</a></p>",
        )

    username = html.escape(
        session["id_claims"].get("preferred_username", "đã đăng nhập")
    )
    return page(
        APP_NAME,
        f"<p>Đã đăng nhập: <strong>{username}</strong></p>"
        "<ul><li><a href='/call/user'>Gọi API user</a></li>"
        "<li><a href='/call/admin'>Gọi API admin</a></li></ul>"
        "<form method='post' action='/logout'><button>Đăng xuất</button></form>",
    )


@app.get("/login")
def login() -> RedirectResponse:
    config = get_oidc_config()
    session_id = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    sessions[session_id] = {
        "pending": {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
        }
    }
    query = urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(
        f"{config['authorization_endpoint']}?{query}",
        status_code=302,
    )
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=900,
        path="/",
    )
    return response


@app.get("/callback", response_class=HTMLResponse)
def callback(request: Request, code: str | None = None, state: str | None = None):
    session_id, session = get_session(request)
    pending = session.get("pending") if session else None
    if not code or not state or not pending or not hmac.compare_digest(
        state, pending["state"]
    ):
        raise HTTPException(status_code=400, detail="Invalid OIDC callback state")

    config = get_oidc_config()
    try:
        token_response = requests.post(
            internalize_keycloak_url(config["token_endpoint"]),
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": pending["verifier"],
            },
            timeout=5,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Keycloak authorization-code exchange failed (network error): {exc}",
        ) from exc
    if not token_response.ok:
        try:
            err_data = token_response.json()
            err_desc = err_data.get("error_description") or err_data.get("error") or token_response.text
        except Exception:
            err_desc = token_response.text
        raise HTTPException(
            status_code=502,
            detail=f"Keycloak authorization-code exchange failed ({token_response.status_code}): {err_desc}",
        )
    try:
        tokens = token_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Keycloak authorization-code exchange failed (invalid JSON response)",
        ) from exc
    id_claims = validate_id_token(
        tokens.get("id_token", ""),
        pending["nonce"],
        config["jwks_uri"],
    )
    session.pop("pending")
    session["access_token"] = tokens["access_token"]
    session["id_claims"] = id_claims
    return RedirectResponse("/", status_code=303)


@app.get("/call/{api_name}", response_class=HTMLResponse)
def call_api(request: Request, api_name: str) -> HTMLResponse:
    _, session = get_session(request)
    if not session or "access_token" not in session:
        return RedirectResponse("/login", status_code=303)
    if api_name not in {"user", "admin"}:
        raise HTTPException(status_code=404, detail="Unknown API")

    try:
        response = requests.get(
            f"{RESOURCE_SERVER_URL}/api/{api_name}",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=5,
        )
        result = response.text
        status = response.status_code
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach the {APP_NAME} resource server",
        ) from exc
    return page(
        f"{APP_NAME}: API {api_name} (HTTP {status})",
        f"<pre>{html.escape(result)}</pre><p><a href='/'>Quay lại</a></p>",
    )


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    session_id, _ = get_session(request)
    if session_id:
        sessions.pop(session_id, None)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
