"""
URL resolving helpers that emulate a browser's behavior when a user types a bare domain.

Rules:
- Try HTTPS first with redirects allowed.
- On connection/SSL errors, fall back to HTTP.
- Return the final URL after redirects when possible; otherwise, return the attempted URL.
"""

from __future__ import annotations

from typing import Optional

import requests


def resolve_browser_like_url(domain: str, timeout_s: float = 10.0) -> str:
    """Resolve a bare domain to a concrete URL similarly to a browser input field.

    Tries https://domain first; if it fails due to network/SSL issues, tries http://domain.
    Returns the final URL after redirects when available; otherwise, returns the original attempt.
    """
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/124.0 Safari/537.36'
    })

    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    # Try HTTPS first
    try:
        # Use tuple timeout to cap connect and read separately
        resp = session.get(https_url, timeout=(10, max(1, int(timeout_s) - 10)), allow_redirects=True)
        return getattr(resp, 'url', https_url) or https_url
    except requests.exceptions.SSLError:
        # SSL handshake failed; fall back to HTTP
        pass
    except requests.exceptions.ConnectionError:
        # Host/port unreachable over HTTPS; fall back to HTTP
        pass
    except requests.RequestException:
        # Some other HTTPS error; still try HTTP
        pass

    # Try HTTP as fallback
    try:
        resp = session.get(http_url, timeout=(10, max(1, int(timeout_s) - 10)), allow_redirects=True)
        return getattr(resp, 'url', http_url) or http_url
    except requests.RequestException:
        # As a last resort, prefer HTTPS canonical form
        return https_url


