"""HTTP request representation — from raw file or from URL."""

from typing import Dict, Optional
from urllib.parse import parse_qs, urlsplit, urlunsplit
import json


def _flatten_qs(qs: dict) -> dict:
    """Flatten parse_qs output: {'key': ['val']} → {'key': 'val'}."""
    return {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in qs.items()}


class Request:
    """
    Represents an HTTP request to scan.
    Can be built from a raw request file (parse) or from a URL (from_url).
    """

    def __init__(self, requestFilename: str = ""):
        self.method = ""
        self.path = ""
        self.parameters: Dict = {}
        self.headers: Dict = {}
        self.body = {}
        self.host = ""
        self.requestFilename = requestFilename

    # ── Build from raw request file ────────────────────────────

    def parse(self) -> Dict:
        with open(self.requestFilename, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read().replace("\r\n", "\n")

        head, _, body_raw = raw.partition("\n\n")
        if not head.strip():
            raise ValueError("Request file is empty.")

        lines = [l for l in head.split("\n") if l.strip()]

        # Request line: METHOD SP PATH [SP HTTP/x.y]
        parts0 = lines[0].split()
        if len(parts0) < 2:
            raise ValueError(f"Invalid request line: {lines[0]!r}")
        self.method = parts0[0]
        raw_path = parts0[1]

        # Separate path and query
        url_parts = urlsplit(raw_path)
        self.path = url_parts.path
        self.parameters = _flatten_qs(parse_qs(url_parts.query, keep_blank_values=True))

        # Headers
        self.headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                self.headers[k.strip()] = v.strip()

        # Body
        self.body = {}
        ctype = self.headers.get("Content-Type", "").lower()
        body_raw = body_raw.strip()
        if body_raw:
            if "application/json" in ctype:
                try:
                    self.body = json.loads(body_raw)
                except Exception:
                    self.body = body_raw
            elif "application/x-www-form-urlencoded" in ctype:
                self.body = dict(parse_qs(body_raw, keep_blank_values=True))
            else:
                self.body = body_raw

        # Host
        self.host = self.headers.get('Host', self.headers.get('host', ''))
        self.headers.pop('Content-Length', None)

        return {
            'host': self.host, 'method': self.method, 'path': self.path,
            'parameters': self.parameters, 'headers': self.headers, 'body': self.body,
        }

    # ── Build from URL string ──────────────────────────────────

    @classmethod
    def from_url(
        cls,
        url: str,
        method: str = "GET",
        body: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        content_type: str = "",
    ) -> "Request":
        """
        Build a Request from a URL + optional body.

        Examples:
            Request.from_url("http://example.com/?id=1")
            Request.from_url("http://example.com/login", method="POST",
                             body={"user": "", "pass": ""},
                             content_type="application/x-www-form-urlencoded")
        """
        req = cls()
        parts = urlsplit(url)

        req.host = parts.hostname or ""
        if parts.port and parts.port not in (80, 443):
            req.host = f"{req.host}:{parts.port}"

        req.method = method.upper()
        req.path = parts.path or "/"
        req.parameters = _flatten_qs(parse_qs(parts.query, keep_blank_values=True))

        req.headers = headers or {}
        if "Host" not in req.headers and "host" not in req.headers:
            req.headers["Host"] = req.host
        if content_type:
            req.headers["Content-Type"] = content_type

        req.body = body or {}

        return req

    # ── Utility ────────────────────────────────────────────────

    @property
    def full_url(self) -> str:
        """Reconstruct the full URL for display purposes."""
        scheme = "https"  # default
        query = "&".join(
            f"{k}={v[0] if isinstance(v, list) else v}"
            for k, v in self.parameters.items()
        ) if self.parameters else ""
        return urlunsplit((scheme, self.host, self.path, query, ""))

    def __str__(self) -> str:
        return (f"Method: {self.method}\nPath: {self.path}\nHost: {self.host}\n"
                f"Parameters: {self.parameters}\nHeaders: {self.headers}\nBody: {self.body}")

    def __repr__(self) -> str:
        return f"<Request {self.method} {self.host}{self.path}>"
