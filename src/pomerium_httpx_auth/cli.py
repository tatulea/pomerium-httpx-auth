from __future__ import annotations

import argparse
import sys
from typing import Iterable

import httpx

from .auth import PomeriumAuth


def _format_headers(headers: httpx.Headers) -> Iterable[str]:
    for key, value in headers.items():
        yield f"{key}: {value}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pomerium-httpx-auth",
        description=(
            "Run a Pomerium-authenticated request and print status/headers."
        ),
    )
    parser.add_argument("url", help="Pomerium-protected URL to request")
    args = parser.parse_args(argv)

    auth = PomeriumAuth(cache=False, open_browser=True)

    try:
        with httpx.Client(http2=True, auth=auth, follow_redirects=True) as client:
            response = client.get(args.url)
    except Exception as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print(f"Status: {response.status_code}")
    for line in _format_headers(response.headers):
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
