"""CSRF token detection and refresh utilities.

Provides anti-CSRF token detection similar to sqlmap's approach:
  1. Identify form fields that look like CSRF tokens (by name pattern)
  2. Fetch fresh tokens from the original page before each scan request
"""

import re
from html.parser import HTMLParser
from typing import Dict, List

import httpx


# ── Token field name patterns ──────────────────────────────────

_CSRF_PATTERNS = [
    re.compile(r"csrf", re.I),
    re.compile(r"xsrf", re.I),
    re.compile(r"token", re.I),
    re.compile(r"nonce", re.I),
    re.compile(r"authenticity", re.I),
    re.compile(r"__RequestVerificationToken", re.I),
    re.compile(r"_token", re.I),
    re.compile(r"csrfmiddlewaretoken", re.I),
    re.compile(r"_csrf_token", re.I),
    re.compile(r"form_key", re.I),
    re.compile(r"anti[-_]?forgery", re.I),
]

_CSRF_EXCLUSIONS = [
    re.compile(r"^(username|password|email|search|query|q|s|id|name|url)$", re.I),
    re.compile(r"^(file|host|lang|page|action|submit|button|type)$", re.I),
]


def is_csrf_field(field_name: str) -> bool:
    """Check if a form field name looks like an anti-CSRF token."""
    for excl in _CSRF_EXCLUSIONS:
        if excl.search(field_name):
            return False
    for pat in _CSRF_PATTERNS:
        if pat.search(field_name):
            return True
    return False


def detect_csrf_fields(params: Dict) -> List[str]:
    """Return list of parameter names that look like CSRF tokens."""
    return [name for name in params if is_csrf_field(name)]


# ── Token extraction from HTML ─────────────────────────────────

class _HiddenInputExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden_inputs: Dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attr_dict = dict(attrs)
            if attr_dict.get("type", "").lower() == "hidden":
                name = attr_dict.get("name", "")
                value = attr_dict.get("value", "")
                if name:
                    self.hidden_inputs[name] = value


def extract_hidden_inputs(html: str) -> Dict[str, str]:
    parser = _HiddenInputExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.hidden_inputs


async def async_fetch_csrf_tokens(
    client: httpx.AsyncClient,
    page_url: str,
    csrf_fields: List[str],
) -> Dict[str, str]:
    """Async: fetch the page and extract fresh CSRF token values."""
    if not csrf_fields:
        return {}
    try:
        resp = await client.get(page_url, follow_redirects=True)
        if resp.status_code != 200:
            return {}
        hidden = extract_hidden_inputs(resp.text or "")
        return {f: hidden[f] for f in csrf_fields if f in hidden}
    except Exception:
        return {}
