"""CSRF token detection and refresh utilities.

Provides anti-CSRF token detection similar to sqlmap's approach:
  1. Identify form fields that look like CSRF tokens (by name pattern)
  2. Fetch fresh tokens from the original page before each scan request
"""

import re
from html.parser import HTMLParser
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin

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
    re.compile(r"csrfmiddlewaretoken", re.I),   # Django
    re.compile(r"_csrf_token", re.I),
    re.compile(r"form_key", re.I),              # Magento
    re.compile(r"anti[-_]?forgery", re.I),
]

# Field names that are NOT CSRF tokens even if they match patterns above
_CSRF_EXCLUSIONS = [
    re.compile(r"^(username|password|email|search|query|q|s|id|name|url)$", re.I),
    re.compile(r"^(file|host|lang|page|action|submit|button|type)$", re.I),
]


def is_csrf_field(field_name: str) -> bool:
    """Check if a form field name looks like an anti-CSRF token."""
    # First check exclusions
    for excl in _CSRF_EXCLUSIONS:
        if excl.search(field_name):
            return False
    # Then check CSRF patterns
    for pat in _CSRF_PATTERNS:
        if pat.search(field_name):
            return True
    return False


def detect_csrf_fields(params: Dict) -> List[str]:
    """Return list of parameter names that look like CSRF tokens."""
    return [name for name in params if is_csrf_field(name)]


# ── Token extraction from HTML ─────────────────────────────────

class _HiddenInputExtractor(HTMLParser):
    """Extract hidden input fields from HTML forms."""

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
    """Extract all hidden input name→value pairs from HTML."""
    parser = _HiddenInputExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.hidden_inputs


def fetch_csrf_tokens(
    client: httpx.Client,
    page_url: str,
    csrf_fields: List[str],
) -> Dict[str, str]:
    """Fetch the page and extract fresh CSRF token values.

    Args:
        client: httpx.Client to use for the request
        page_url: URL of the page containing the form
        csrf_fields: list of field names to extract values for

    Returns:
        Dict of field_name → fresh_token_value
    """
    if not csrf_fields:
        return {}

    try:
        resp = client.get(page_url, follow_redirects=True)
        if resp.status_code != 200:
            return {}

        hidden = extract_hidden_inputs(resp.text or "")
        tokens = {}
        for field in csrf_fields:
            if field in hidden:
                tokens[field] = hidden[field]
        return tokens
    except Exception:
        return {}
