"""Crawler — BFS link/form discovery using stdlib html.parser."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, parse_qs
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

import httpx

from webscanner.parsers.request import Request


# ── HTML parsers ───────────────────────────────────────────────

@dataclass
class FormData:
    """Represents an HTML <form> with its inputs."""
    action: str = ""
    method: str = "GET"
    inputs: Dict[str, str] = field(default_factory=dict)  # name → default value


class _LinkExtractor(HTMLParser):
    """Extract <a href> links from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


class _FormExtractor(HTMLParser):
    """Extract <form> elements with their inputs from HTML."""

    def __init__(self):
        super().__init__()
        self.forms: List[FormData] = []
        self._current_form: Optional[FormData] = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "form":
            self._current_form = FormData(
                action=attr_dict.get("action", ""),
                method=attr_dict.get("method", "GET").upper(),
            )

        elif self._current_form is not None:
            if tag == "input":
                name = attr_dict.get("name", "")
                input_type = attr_dict.get("type", "text").lower()
                if name and input_type not in ("submit", "button", "image", "reset"):
                    self._current_form.inputs[name] = attr_dict.get("value", "")

            elif tag == "textarea":
                name = attr_dict.get("name", "")
                if name:
                    self._current_form.inputs[name] = ""

            elif tag == "select":
                name = attr_dict.get("name", "")
                if name:
                    self._current_form.inputs[name] = ""

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ── Helper functions ───────────────────────────────────────────

def extract_links(html: str) -> List[str]:
    """Extract all <a href> values from HTML."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.links


def extract_forms(html: str) -> List[FormData]:
    """Extract all <form> elements with their inputs from HTML."""
    parser = _FormExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.forms


def is_same_origin(base_url: str, target_url: str) -> bool:
    """Check if target_url is same-origin as base_url."""
    base = urlsplit(base_url)
    target = urlsplit(target_url)
    return base.scheme == target.scheme and base.netloc == target.netloc


def normalize_url(url: str) -> str:
    """Normalize URL by removing fragments and trailing slashes on path."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme}://{parts.netloc}{path}"


def should_skip_url(url: str) -> bool:
    """Skip non-HTTP URLs and static assets."""
    lower = url.lower()
    # Skip non-HTTP
    if any(lower.startswith(s) for s in ("javascript:", "mailto:", "tel:", "data:", "#")):
        return True
    # Skip static files
    skip_ext = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
                ".zip", ".tar", ".gz", ".mp4", ".mp3", ".webp")
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in skip_ext)


# ── Crawler class ──────────────────────────────────────────────

class Crawler:
    """
    BFS crawler that discovers links and forms on a target website.

    Usage:
        crawler = Crawler(client, logger, max_depth=2)
        requests = crawler.crawl("http://example.com/")
    """

    def __init__(self, client: httpx.Client, logger=None, max_depth: int = 2):
        self.client = client
        self.logger = logger
        self.max_depth = max_depth

    def crawl(self, start_url: str) -> List[Request]:
        """
        BFS crawl from start_url.
        Returns a list of Request objects generated from discovered forms and
        URLs with query parameters.
        """
        visited: Set[str] = set()
        requests: List[Request] = []
        seen_requests: Set[str] = set()  # dedup key: "METHOD path params_key"

        # BFS queue: (url, depth)
        queue: List[Tuple[str, int]] = [(start_url, 0)]

        if self.logger:
            self.logger.info(f"Crawling {start_url} (max depth: {self.max_depth})")

        while queue:
            url, depth = queue.pop(0)

            # Normalize and dedup
            norm = normalize_url(url)
            if norm in visited:
                continue
            visited.add(norm)

            if self.logger:
                self.logger.debug(f"Visiting [{depth}] {url}")

            # Fetch the page
            html = self._fetch(url)
            if html is None:
                continue

            # ── Extract forms → Request objects ────────────────
            forms = extract_forms(html)
            for form in forms:
                req = self._form_to_request(url, form)
                if req:
                    key = self._request_key(req)
                    if key not in seen_requests:
                        seen_requests.add(key)
                        requests.append(req)
                        if self.logger:
                            self.logger.info(
                                f"  Found form: {req.method} {req.host}{req.path} "
                                f"({len(form.inputs)} inputs)"
                            )

            # ── Extract links with query params → Request objects
            parts = urlsplit(url)
            if parts.query:
                req = Request.from_url(url, method="GET")
                key = self._request_key(req)
                if key not in seen_requests:
                    seen_requests.add(key)
                    requests.append(req)
                    if self.logger:
                        params = list(req.parameters.keys())
                        self.logger.info(
                            f"  Found URL params: GET {req.host}{req.path} "
                            f"({', '.join(params)})"
                        )

            # ── Queue child links if within depth ──────────────
            if depth < self.max_depth:
                links = extract_links(html)
                for href in links:
                    abs_url = urljoin(url, href)
                    if should_skip_url(abs_url):
                        continue
                    if not is_same_origin(start_url, abs_url):
                        continue
                    norm_child = normalize_url(abs_url)
                    if norm_child not in visited:
                        queue.append((abs_url, depth + 1))

        if self.logger:
            self.logger.ok(
                f"Crawl complete: {len(visited)} pages visited, "
                f"{len(requests)} scannable targets found"
            )

        return requests

    # ── Internal helpers ───────────────────────────────────────

    def _fetch(self, url: str) -> Optional[str]:
        """GET a URL and return its HTML body, or None on error."""
        try:
            resp = self.client.get(url, follow_redirects=True)
            ctype = resp.headers.get("content-type", "").lower()
            if "text/html" not in ctype and "application/xhtml" not in ctype:
                return None
            return resp.text
        except (httpx.TimeoutException, httpx.ConnectError,
                httpx.RemoteProtocolError, Exception) as exc:
            if self.logger:
                self.logger.warn(f"Crawl fetch failed: {url} — {exc}")
            return None

    def _form_to_request(self, page_url: str, form: FormData) -> Optional[Request]:
        """Convert a FormData into a scannable Request object."""
        if not form.inputs:
            return None

        # Resolve form action
        action = form.action or page_url
        abs_action = urljoin(page_url, action)
        parts = urlsplit(abs_action)

        method = form.method or "GET"

        if method == "GET":
            # Form inputs go as query parameters
            req = Request.from_url(abs_action, method="GET")
            for name, val in form.inputs.items():
                req.parameters[name] = val or ""
        else:
            # Form inputs go as body (form-urlencoded)
            req = Request.from_url(
                abs_action,
                method=method,
                body={name: (val or "") for name, val in form.inputs.items()},
                content_type="application/x-www-form-urlencoded",
            )

        return req

    @staticmethod
    def _request_key(req: Request) -> str:
        """Generate a dedup key for a Request."""
        params_key = ",".join(sorted(req.parameters.keys()))
        body_key = ",".join(sorted(req.body.keys())) if isinstance(req.body, dict) else ""
        return f"{req.method}|{req.host}{req.path}|{params_key}|{body_key}"
