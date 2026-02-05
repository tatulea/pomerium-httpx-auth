# pomerium-httpx-auth

HTTPX authentication helper for Pomerium-protected services. It performs the Pomerium SSO login flow in the browser, captures the callback JWT via a local listener, and automatically attaches `Authorization: Pomerium <jwt>` to requests. It supports both `httpx.Client` and `httpx.AsyncClient` and can optionally cache tokens on disk per host.

## What it does

- Fetches the Pomerium login URL via `/.pomerium/api/v1/login` using HTTP/2.
- Starts a local callback listener on `127.0.0.1` with an ephemeral port.
- Opens the browser for the user to authenticate.
- Captures the JWT on the callback and uses it for subsequent requests.
- Automatically re-authenticates if a request is redirected to `/.pomerium/sign_in`.
- Optional disk cache per host with safe permissions.

## Installation

```sh
uv pip install pomerium-httpx-auth
```

## Usage

### Sync client

```python
import httpx
from pomerium_httpx_auth import PomeriumAuth

auth = PomeriumAuth(cache=True)

with httpx.Client(http2=True, auth=auth) as client:
    r = client.get("https://your-protected-service.example.com")
    print(r.status_code)
```

### Async client

```python
import httpx
from pomerium_httpx_auth import PomeriumAuth

auth = PomeriumAuth(cache=True)

async def main() -> None:
    async with httpx.AsyncClient(http2=True, auth=auth) as client:
        r = await client.get("https://your-protected-service.example.com")
        print(r.status_code)
```

### CLI

Install the package, then run:

```sh
pomerium-httpx-auth https://your-protected-service.example.com
```

The command performs a single authenticated GET request, then prints the HTTP status code and response headers (no body). It uses in-memory tokens only.

### Restrict to specific domains

```python
from pomerium_httpx_auth import PomeriumAuth

auth = PomeriumAuth(authenticated_domains=["example.com", "internal.example.com"], cache=True)
```

## Configuration

- `authenticated_domains`: Optional allowlist of domains. If set, only requests to those domains (or their subdomains) are authenticated.
- `cache`: Enable disk caching. Default is `False`.
- `cache_dir`: Optional custom cache directory. If not set and `cache=True`, the per-user cache directory is used.
- `open_browser`: Open the browser automatically. Default is `True`.

## Cache behavior

- Tokens are cached per host.
- Disk caching is opt-in.
- The cache directory is created with `0700` permissions and token files are written with `0600` permissions.

Default cache directory by platform:

- macOS: `~/Library/Caches/pomerium-httpx-auth`
- Linux: `~/.cache/pomerium-httpx-auth` (or `$XDG_CACHE_HOME/pomerium-httpx-auth`)
- Windows: `%LOCALAPPDATA%/pomerium-httpx-auth`

## Notes and limitations

- The callback listener always binds to `127.0.0.1` and an ephemeral port. This is not configurable.
- Re-authentication requires a buffered request body. Streaming request bodies cannot be replayed if a re-auth is needed.
- This library assumes the Pomerium login endpoint returns the auth URL as plain text.

## Development

Install test dependencies and run tests:

```sh
uv pip install -e ".[test]"
uv run pytest
```

## License

MIT
