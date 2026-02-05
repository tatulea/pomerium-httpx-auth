from __future__ import annotations

import base64
import json
import os
import time

import httpx
import pytest

from pomerium_httpx_auth import PomeriumAuth
from pomerium_httpx_auth.auth import _host_cache_key, _parse_jwt_exp


def _make_jwt(expiry: int) -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"exp": expiry}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.signature"


def test_parse_jwt_exp_defaults_when_missing() -> None:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "user"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"{header_b64}.{payload_b64}.sig"

    expiry = _parse_jwt_exp(jwt)
    assert expiry >= int(time.time() + 3500)


def test_cache_key_is_stable() -> None:
    key = _host_cache_key("example.com")
    assert key == _host_cache_key("example.com")


def test_auth_adds_header(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _make_jwt(int(time.time() + 3600))
    auth = PomeriumAuth(cache=False, open_browser=False)

    def fake_authenticate(_: httpx.URL) -> str:
        return jwt

    monkeypatch.setattr(auth, "_authenticate_sync", fake_authenticate)

    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    with httpx.Client(transport=transport, auth=auth) as client:
        response = client.get("https://example.com/resource")

    assert response.request.headers["Authorization"] == f"Pomerium {jwt}"


def test_reauth_on_sign_in_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt1 = _make_jwt(int(time.time() + 3600))
    jwt2 = _make_jwt(int(time.time() + 7200))
    auth = PomeriumAuth(cache=False, open_browser=False)

    calls = {"count": 0}

    def fake_authenticate(_: httpx.URL) -> str:
        calls["count"] += 1
        return jwt1 if calls["count"] == 1 else jwt2

    monkeypatch.setattr(auth, "_authenticate_sync", fake_authenticate)

    def handler(request: httpx.Request) -> httpx.Response:
        if calls["count"] == 1:
            return httpx.Response(302, headers={"Location": "https://foo/.pomerium/sign_in?"})
        return httpx.Response(200, request=request)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, auth=auth) as client:
        response = client.get("https://example.com/resource")

    assert response.status_code == 200
    assert response.request.headers["Authorization"] == f"Pomerium {jwt2}"
    assert calls["count"] == 2


def test_disk_cache_round_trip(tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _make_jwt(int(time.time() + 3600))
    auth = PomeriumAuth(cache=True, cache_dir=str(tmp_path), open_browser=False)

    monkeypatch.setattr(auth, "_authenticate_sync", lambda _: jwt)

    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    with httpx.Client(transport=transport, auth=auth) as client:
        client.get("https://example.com/resource")

    cache_file = tmp_path / f"{_host_cache_key('example.com')}.json"
    assert cache_file.exists()

    auth2 = PomeriumAuth(cache=True, cache_dir=str(tmp_path), open_browser=False)
    transport2 = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    with httpx.Client(transport=transport2, auth=auth2) as client:
        response = client.get("https://example.com/other")

    assert response.request.headers["Authorization"] == f"Pomerium {jwt}"


@pytest.mark.asyncio
async def test_async_auth_adds_header(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _make_jwt(int(time.time() + 3600))
    auth = PomeriumAuth(cache=False, open_browser=False)

    async def fake_authenticate(_: httpx.URL) -> str:
        return jwt

    monkeypatch.setattr(auth, "_authenticate_async", fake_authenticate)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        response = await client.get("https://example.com/resource")

    assert response.request.headers["Authorization"] == f"Pomerium {jwt}"
