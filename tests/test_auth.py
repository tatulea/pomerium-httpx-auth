from __future__ import annotations

import os

import httpx
import pytest

from pomerium_httpx_auth import PomeriumAuth
from pomerium_httpx_auth.auth import _host_cache_key

_FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.signature"


def test_cache_key_is_stable() -> None:
    key = _host_cache_key("example.com")
    assert key == _host_cache_key("example.com")


def test_auth_adds_header(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _FAKE_JWT
    auth = PomeriumAuth(cache=False, open_browser=False)

    def fake_authenticate(_: httpx.URL) -> str:
        return jwt

    monkeypatch.setattr(auth, "_authenticate_sync", fake_authenticate)

    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    with httpx.Client(transport=transport, auth=auth) as client:
        response = client.get("https://example.com/resource")

    assert response.request.headers["Authorization"] == f"Pomerium {jwt}"


def test_reauth_on_sign_in_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt1 = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwibiI6MX0.sig1"
    jwt2 = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwibiI6Mn0.sig2"
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


def test_reauth_on_401(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt1 = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwibiI6MX0.sig1"
    jwt2 = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwibiI6Mn0.sig2"
    auth = PomeriumAuth(cache=False, open_browser=False)

    calls = {"count": 0}

    def fake_authenticate(_: httpx.URL) -> str:
        calls["count"] += 1
        return jwt1 if calls["count"] == 1 else jwt2

    monkeypatch.setattr(auth, "_authenticate_sync", fake_authenticate)

    def handler(request: httpx.Request) -> httpx.Response:
        if calls["count"] == 1:
            return httpx.Response(401)
        return httpx.Response(200, request=request)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, auth=auth) as client:
        response = client.get("https://example.com/resource")

    assert response.status_code == 200
    assert response.request.headers["Authorization"] == f"Pomerium {jwt2}"
    assert calls["count"] == 2


def test_disk_cache_round_trip(tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _FAKE_JWT
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
    jwt = _FAKE_JWT
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
