from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import httpx
import http.server

_LOG = logging.getLogger("pomerium_httpx_auth")

_CALLBACK_HOST = "127.0.0.1"
_TIME_DRIFT_SECONDS = 60
_DEFAULT_CALLBACK_TIMEOUT_SECONDS = 300


class PomeriumAuthError(RuntimeError):
    """Raised when the Pomerium authentication flow fails."""


@dataclass
class _TokenEntry:
    jwt: str
    expiry: int


class _TokenCache:
    def __init__(self, enabled: bool, cache_dir: Optional[Path]) -> None:
        self._enabled = enabled
        self._cache_dir = self._init_cache_dir(cache_dir) if enabled else None
        self._memory: dict[str, _TokenEntry] = {}

    def get(self, host: str) -> Optional[str]:
        entry = self._memory.get(host)
        if entry and self._is_valid(entry.expiry):
            return entry.jwt

        if entry and not self._is_valid(entry.expiry):
            self._memory.pop(host, None)

        if not self._enabled or not self._cache_dir:
            return None

        disk_entry = self._load_from_disk(host)
        if disk_entry and self._is_valid(disk_entry.expiry):
            self._memory[host] = disk_entry
            return disk_entry.jwt

        if disk_entry and not self._is_valid(disk_entry.expiry):
            self._delete_from_disk(host)

        return None

    def set(self, host: str, jwt: str) -> None:
        expiry = _parse_jwt_exp(jwt)
        entry = _TokenEntry(jwt=jwt, expiry=expiry)
        self._memory[host] = entry
        if self._enabled and self._cache_dir:
            self._store_to_disk(host, entry)

    @staticmethod
    def _is_valid(expiry: int) -> bool:
        return expiry > int(time.time() + _TIME_DRIFT_SECONDS)

    @staticmethod
    def _init_cache_dir(cache_dir: Optional[Path]) -> Path:
        base_dir = cache_dir if cache_dir else _default_cache_dir()
        base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except PermissionError:
            pass
        return base_dir

    def _cache_path(self, host: str) -> Path:
        key = _host_cache_key(host)
        assert self._cache_dir is not None
        return self._cache_dir / f"{key}.json"

    def _load_from_disk(self, host: str) -> Optional[_TokenEntry]:
        path = self._cache_path(host)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        jwt = data.get("jwt")
        expiry = data.get("expiry")
        if not isinstance(jwt, str) or not isinstance(expiry, int):
            return None
        return _TokenEntry(jwt=jwt, expiry=expiry)

    def _store_to_disk(self, host: str, entry: _TokenEntry) -> None:
        path = self._cache_path(host)
        payload = {"host": host, "expiry": entry.expiry, "jwt": entry.jwt}
        try:
            tmp_path = path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(payload, indent=2))
            try:
                os.chmod(tmp_path, 0o600)
            except PermissionError:
                pass
            os.replace(tmp_path, path)
            try:
                os.chmod(path, 0o600)
            except PermissionError:
                pass
        except OSError as exc:
            raise PomeriumAuthError(f"Failed to store JWT cache: {exc}") from exc

    def _delete_from_disk(self, host: str) -> None:
        path = self._cache_path(host)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return


class _CallbackServer(http.server.HTTPServer):
    def __init__(self, validation_token: str) -> None:
        self.validation_token = validation_token
        self.jwt: Optional[str] = None
        self._finished = threading.Event()
        super().__init__((_CALLBACK_HOST, 0), _CallbackHandler)
        self.timeout = 0.5


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        expected_prefix = f"/auth/{self.server.validation_token}"
        if not parsed.path.startswith(expected_prefix):
            self._send_response(404, "Not found.")
            return

        params = urllib.parse.parse_qs(parsed.query)
        jwt = params.get("pomerium_jwt", [None])[0]
        if not jwt:
            self._send_response(400, "Missing token.")
            return

        self.server.jwt = jwt
        self.server._finished.set()
        self._send_response(200, "Authentication successful. You may close this tab.")

    def _send_response(self, status: int, message: str) -> None:
        body = _render_callback_html(status, message).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True


class PomeriumAuth(httpx.Auth):
    def __init__(
        self,
        *,
        authenticated_domains: Optional[Iterable[str]] = None,
        cache: bool = False,
        cache_dir: Optional[str] = None,
        open_browser: bool = True,
    ) -> None:
        self._authenticated_domains = [d.lower() for d in authenticated_domains or []]
        self._open_browser = open_browser
        cache_path = Path(cache_dir) if cache_dir else None
        self._cache = _TokenCache(enabled=cache, cache_dir=cache_path)
        self._lock = threading.Lock()
        self._async_lock = asyncio.Lock()

    def auth_flow(self, request: httpx.Request) -> Iterable[httpx.Request]:
        if not self._should_authenticate(request.url):
            yield request
            return

        body = _read_request_body_sync(request)
        token = self._get_token_sync(request.url)
        request.headers["Authorization"] = f"Pomerium {token}"
        response = yield request

        if _is_sign_in_redirect(response):
            token = self._refresh_token_sync(request.url)
            new_request = _clone_request(request, body)
            new_request.headers["Authorization"] = f"Pomerium {token}"
            yield new_request

    async def async_auth_flow(self, request: httpx.Request) -> Iterable[httpx.Request]:
        if not self._should_authenticate(request.url):
            yield request
            return

        body = await _read_request_body_async(request)
        token = await self._get_token_async(request.url)
        request.headers["Authorization"] = f"Pomerium {token}"
        response = yield request

        if _is_sign_in_redirect(response):
            token = await self._refresh_token_async(request.url)
            new_request = _clone_request(request, body)
            new_request.headers["Authorization"] = f"Pomerium {token}"
            yield new_request

    def _should_authenticate(self, url: httpx.URL) -> bool:
        if url.scheme != "https":
            return False

        host = (url.host or "").lower()
        if not host:
            return False

        if not self._authenticated_domains:
            return True

        for domain in self._authenticated_domains:
            if host == domain or host.endswith(f".{domain}"):
                return True
        return False

    def _get_token_sync(self, url: httpx.URL) -> str:
        host = _require_host(url)
        cached = self._cache.get(host)
        if cached:
            return cached

        with self._lock:
            cached = self._cache.get(host)
            if cached:
                return cached
            jwt = self._authenticate_sync(url)
            self._cache.set(host, jwt)
            return jwt

    async def _get_token_async(self, url: httpx.URL) -> str:
        host = _require_host(url)
        cached = self._cache.get(host)
        if cached:
            return cached

        async with self._async_lock:
            cached = self._cache.get(host)
            if cached:
                return cached
            jwt = await self._authenticate_async(url)
            self._cache.set(host, jwt)
            return jwt

    def _refresh_token_sync(self, url: httpx.URL) -> str:
        host = _require_host(url)
        with self._lock:
            jwt = self._authenticate_sync(url)
            self._cache.set(host, jwt)
            return jwt

    async def _refresh_token_async(self, url: httpx.URL) -> str:
        host = _require_host(url)
        async with self._async_lock:
            jwt = await self._authenticate_async(url)
            self._cache.set(host, jwt)
            return jwt

    def _authenticate_sync(self, url: httpx.URL) -> str:
        server, callback_url = _start_callback_server()
        login_url = _build_login_url(url, callback_url)
        auth_url = _fetch_authentication_url(login_url)
        _maybe_open_browser(auth_url, self._open_browser)
        try:
            jwt = _wait_for_callback(server, _DEFAULT_CALLBACK_TIMEOUT_SECONDS)
        finally:
            server.server_close()
        if not jwt:
            raise PomeriumAuthError("Authentication callback did not return a token")
        return jwt

    async def _authenticate_async(self, url: httpx.URL) -> str:
        server, callback_url = _start_callback_server()
        login_url = _build_login_url(url, callback_url)
        auth_url = await _fetch_authentication_url_async(login_url)
        _maybe_open_browser(auth_url, self._open_browser)
        try:
            jwt = await asyncio.to_thread(
                _wait_for_callback, server, _DEFAULT_CALLBACK_TIMEOUT_SECONDS
            )
        finally:
            server.server_close()
        if not jwt:
            raise PomeriumAuthError("Authentication callback did not return a token")
        return jwt


def _start_callback_server() -> tuple[_CallbackServer, str]:
    validation_token = secrets.token_urlsafe(16)
    server = _CallbackServer(validation_token)
    port = server.server_address[1]
    callback_url = f"http://{_CALLBACK_HOST}:{port}/auth/{validation_token}"
    return server, callback_url


def _build_login_url(target_url: httpx.URL, callback_url: str) -> str:
    host = _require_host(target_url)
    query = urllib.parse.urlencode({"pomerium_redirect_uri": callback_url})
    return f"https://{host}/.pomerium/api/v1/login?{query}"


def _fetch_authentication_url(login_url: str) -> str:
    try:
        with httpx.Client(http2=True) as client:
            response = client.get(login_url)
    except httpx.HTTPError as exc:
        raise PomeriumAuthError(f"Failed to query Pomerium login API: {exc}") from exc
    return _validate_login_response(response)


async def _fetch_authentication_url_async(login_url: str) -> str:
    try:
        async with httpx.AsyncClient(http2=True) as client:
            response = await client.get(login_url)
    except httpx.HTTPError as exc:
        raise PomeriumAuthError(f"Failed to query Pomerium login API: {exc}") from exc
    return _validate_login_response(response)


def _validate_login_response(response: httpx.Response) -> str:
    if response.status_code != 200:
        raise PomeriumAuthError(
            f"Unexpected status code from login API: {response.status_code}"
        )
    auth_url = response.text.strip()
    if not auth_url.startswith("https://"):
        raise PomeriumAuthError(
            "Login API did not return an authentication URL"
        )
    return auth_url


def _wait_for_callback(server: _CallbackServer, timeout_seconds: int) -> Optional[str]:
    deadline = time.monotonic() + timeout_seconds
    while not server._finished.is_set():
        server.handle_request()
        if time.monotonic() > deadline:
            raise PomeriumAuthError("Timed out waiting for authentication callback")
    return server.jwt


def _maybe_open_browser(url: str, open_browser: bool) -> None:
    if not open_browser:
        _LOG.info("Open this URL to authenticate: %s", url)
        return
    try:
        webbrowser.open_new_tab(url)
    except Exception as exc:  # pragma: no cover - best effort
        _LOG.warning("Failed to open browser: %s", exc)
        _LOG.info("Open this URL to authenticate: %s", url)


def _require_host(url: httpx.URL) -> str:
    host = url.host
    if not host:
        raise PomeriumAuthError("Target URL is missing a host")
    return host


def _parse_jwt_exp(jwt: str) -> int:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise PomeriumAuthError("Invalid JWT format")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PomeriumAuthError("Failed to decode JWT payload") from exc
    exp = data.get("exp")
    if exp is None:
        return int(time.time() + 3600)
    try:
        return int(exp)
    except (TypeError, ValueError) as exc:
        raise PomeriumAuthError("Invalid exp claim in JWT") from exc


def _host_cache_key(host: str) -> str:
    encoded = base64.urlsafe_b64encode(host.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _default_cache_dir() -> Path:
    home = Path.home()
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = home / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    return base / "pomerium-httpx-auth"


def _is_sign_in_redirect(response: httpx.Response) -> bool:
    locations: list[str] = []
    if response.is_redirect:
        location = response.headers.get("location")
        if location:
            locations.append(location)
    for prior in response.history:
        if prior.is_redirect:
            location = prior.headers.get("location")
            if location:
                locations.append(location)
    return any("/.pomerium/sign_in?" in loc for loc in locations)


def _render_callback_html(status: int, message: str) -> str:
    ok = status < 400
    title = "Authenticated" if ok else "Authentication failed"
    tone = "#1b7f3b" if ok else "#b42318"
    return (
        "<!doctype html>"
        "<html>"
        "<head>"
        "<meta charset=\"utf-8\" />"
        "<title>Pomerium Auth</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
        "margin:0;background:#f6f7f9;color:#111;padding:2rem;}"
        ".card{max-width:560px;width:100%;padding:1.25rem;border:1px solid #e3e6ea;"
        "margin:0 auto;"
        "border-radius:10px;background:#fff;box-shadow:0 2px 10px rgba(0,0,0,0.06);}"
        ".title{font-size:1.1rem;font-weight:600;color:"
        + tone
        + ";margin-bottom:0.5rem;}"
        ".msg{font-size:0.95rem;line-height:1.4;}"
        "</style>"
        "</head>"
        "<body>"
        "<div class=\"card\">"
        "<div class=\"title\">"
        + title
        + "</div>"
        "<div class=\"msg\">"
        + _escape_html(message)
        + "</div>"
        "</div>"
        "</body>"
        "</html>"
    )


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
    )

def _clone_request(request: httpx.Request, body: Optional[bytes]) -> httpx.Request:
    if body is None:
        raise PomeriumAuthError(
            "Cannot re-authenticate streaming request without a buffered body"
        )
    return httpx.Request(
        method=request.method,
        url=request.url,
        headers=request.headers,
        content=body,
        extensions=request.extensions,
    )


def _read_request_body_sync(request: httpx.Request) -> Optional[bytes]:
    reader = getattr(request, "read", None)
    if callable(reader):
        try:
            return reader()
        except Exception:
            return None
    try:
        return request.content
    except Exception:
        return None


async def _read_request_body_async(request: httpx.Request) -> Optional[bytes]:
    reader = getattr(request, "aread", None)
    if callable(reader):
        try:
            return await reader()
        except Exception:
            return None
    try:
        return request.content
    except Exception:
        return None
