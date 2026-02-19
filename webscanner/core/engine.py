"""Scan engine — orchestrates baseline + injection + differential detection.

Handles CSRF token detection and refresh: if a form contains fields that look
like anti-CSRF tokens, the engine fetches fresh tokens before each injection.
"""

import httpx
from copy import deepcopy
from typing import List, Optional
from urllib.parse import urlunsplit, urlsplit

from colorama import Style

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData
from webscanner.core.csrf import detect_csrf_fields, fetch_csrf_tokens
from webscanner.parsers.request import Request

_STOP_HDRS = {"host", "content-length", "transfer-encoding", "content-encoding"}


class Engine:
    def __init__(
        self,
        proxy: str | None = None,
        protocol: str = "https",
        logger=None,
        timeout: int = 15,
    ):
        self.name = "WebScanner"
        self.version = "2.2.0"
        self.protocol = protocol
        self.logger = logger
        self.client = httpx.Client(
            verify=False,
            proxy=proxy,
            follow_redirects=True,
            timeout=timeout,
        )

    # ── host helper ─────────────────────────────────────────────

    def _host(self, req: Request) -> str:
        host = getattr(req, "host", "") or req.headers.get("Host") or req.headers.get("host", "")
        if not host:
            raise ValueError("Host no definido en la request.")
        return host

    # ── FUZZ detection helpers ──────────────────────────────────

    @staticmethod
    def _has_fuzz(value) -> bool:
        if isinstance(value, str):
            return "FUZZ" in value
        if isinstance(value, dict):
            for v in value.values():
                if isinstance(v, list):
                    if any(isinstance(x, str) and "FUZZ" in x for x in v):
                        return True
                elif isinstance(v, str) and "FUZZ" in v:
                    return True
        return False

    @staticmethod
    def _apply_fuzz(value, payload: str):
        """Replace FUZZ in a string, dict, or list-of-strings."""
        if isinstance(value, str):
            return value.replace("FUZZ", payload)
        if isinstance(value, dict):
            out = deepcopy(value)
            for k, v in list(out.items()):
                if isinstance(v, list):
                    out[k] = [x.replace("FUZZ", payload) if isinstance(x, str) else x for x in v]
                elif isinstance(v, str):
                    out[k] = v.replace("FUZZ", payload)
            return out
        return value

    @staticmethod
    def _clean_headers(headers: dict) -> dict:
        """Remove hop-by-hop headers that break httpx."""
        return {k: v for k, v in headers.items() if k.lower() not in _STOP_HDRS}

    # ── page URL helper (for CSRF token refresh) ────────────────

    def _form_page_url(self, request: Request) -> str:
        """Reconstruct the page URL that originally contained the form.

        For a POST /login form on example.com, the form page is
        usually GET /login or the Referer/Origin header.
        """
        host = self._host(request)
        path = request.path if request.path.startswith("/") else f"/{request.path}"
        referer = request.headers.get("Referer") or request.headers.get("referer")
        if referer:
            return referer
        return f"{self.protocol}://{host}{path}"

    # ── send a single request ───────────────────────────────────

    def _send(self, request: Request, url: str, headers: dict, params: dict | None, body) -> Optional[httpx.Response]:
        """Fire one request. Returns None on network errors instead of crashing."""
        clean_h = self._clean_headers(headers)
        is_json = "application/json" in (request.headers.get("Content-Type", "") or "").lower()
        try:
            if is_json and isinstance(body, dict):
                return self.client.request(
                    method=request.method, url=url, headers=clean_h,
                    params=params or None, json=body,
                )
            else:
                return self.client.request(
                    method=request.method, url=url, headers=clean_h,
                    params=params or None, data=body if body else None,
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            if self.logger:
                self.logger.warn(f"Request failed: {exc}")
            return None

    # ── baseline capture ────────────────────────────────────────

    def _capture_baseline(self, request: Request, url: str, headers: dict,
                          params: dict | None, body) -> BaselineData:
        """Send the original request WITHOUT any payload to capture normal behavior."""
        resp = self._send(request, url, headers, params, body)
        if resp is None:
            return BaselineData()
        return BaselineData(
            status_code=resp.status_code,
            body=resp.text or "",
            body_length=len(resp.text or ""),
            elapsed=resp.elapsed.total_seconds(),
            headers=dict(resp.headers),
        )

    # ── CSRF token detection ────────────────────────────────────

    def _detect_and_log_csrf(self, params: dict, body: dict) -> tuple[list[str], list[str]]:
        """Detect CSRF-like fields in query params and body. Returns (query_csrf, body_csrf)."""
        query_csrf = detect_csrf_fields(params) if params else []
        body_csrf = detect_csrf_fields(body) if isinstance(body, dict) else []
        if (query_csrf or body_csrf) and self.logger:
            all_csrf = query_csrf + body_csrf
            self.logger.info(f"  CSRF tokens detected: {', '.join(all_csrf)} (will refresh per request)")
        return query_csrf, body_csrf

    def _refresh_csrf(self, request: Request, params: dict, body: dict,
                      query_csrf: list, body_csrf: list) -> tuple[dict, dict]:
        """Fetch fresh CSRF tokens and inject them into params/body."""
        all_csrf = query_csrf + body_csrf
        if not all_csrf:
            return params, body

        page_url = self._form_page_url(request)
        fresh = fetch_csrf_tokens(self.client, page_url, all_csrf)
        if not fresh:
            return params, body

        # Inject fresh tokens
        new_params = deepcopy(params)
        new_body = deepcopy(body) if isinstance(body, dict) else body
        for field, value in fresh.items():
            if field in query_csrf and isinstance(new_params, dict):
                new_params[field] = value
            if field in body_csrf and isinstance(new_body, dict):
                new_body[field] = value

        return new_params, new_body

    # ── main scan entry point ───────────────────────────────────

    def scan(self, checker: BaseChecker, request: Request) -> List[CheckResult]:
        payloads = checker.get_payloads()
        results: List[CheckResult] = []

        host = self._host(request)
        base_path = request.path if request.path.startswith("/") else f"/{request.path}"
        orig_params = deepcopy(request.parameters) if isinstance(request.parameters, dict) else {}
        orig_body = deepcopy(request.body) if isinstance(request.body, (dict, str)) else {}
        orig_headers = deepcopy(request.headers) if isinstance(request.headers, dict) else {}

        # Detect FUZZ mode
        fuzz_in_path = isinstance(base_path, str) and "FUZZ" in base_path
        fuzz_in_params = self._has_fuzz(orig_params)
        fuzz_in_body = self._has_fuzz(orig_body)
        fuzz_in_headers = self._has_fuzz(orig_headers)
        fuzz_mode = fuzz_in_path or fuzz_in_params or fuzz_in_body or fuzz_in_headers

        base_url = f"{self.protocol}://{host}{base_path}"

        if self.logger:
            self.logger.info(f"Scanning {checker.name} @ {base_url}")

        # Detect CSRF tokens
        query_csrf, body_csrf = self._detect_and_log_csrf(
            orig_params, orig_body if isinstance(orig_body, dict) else {}
        )

        # ── FUZZ mode ──────────────────────────────────────────
        if fuzz_mode:
            # Baseline: send with FUZZ replaced by a harmless value
            bl_path = base_path.replace("FUZZ", "BASELINE_PROBE") if fuzz_in_path else base_path
            bl_params = self._apply_fuzz(orig_params, "BASELINE_PROBE") if fuzz_in_params else orig_params
            bl_body = self._apply_fuzz(orig_body, "BASELINE_PROBE") if fuzz_in_body else orig_body
            bl_headers = self._apply_fuzz(orig_headers, "BASELINE_PROBE") if fuzz_in_headers else orig_headers
            bl_url = f"{self.protocol}://{host}{bl_path}"
            baseline = self._capture_baseline(request, bl_url, bl_headers, bl_params, bl_body)

            total = len(payloads)
            for idx, payload in enumerate(payloads, 1):
                if self.logger and self.logger.verbose >= 2:
                    self.logger.debug(f"[{idx}/{total}] FUZZ = {self.logger.PAY}{payload}{Style.RESET_ALL}")

                path_mut = base_path.replace("FUZZ", payload) if fuzz_in_path else base_path
                url = f"{self.protocol}://{host}{path_mut}"
                params_mut = self._apply_fuzz(orig_params, payload) if fuzz_in_params else orig_params
                body_mut = self._apply_fuzz(orig_body, payload) if fuzz_in_body else orig_body
                headers_mut = self._apply_fuzz(orig_headers, payload) if fuzz_in_headers else orig_headers

                resp = self._send(request, url, headers_mut, params_mut, body_mut)
                if resp is None:
                    continue

                result = checker.check(baseline, resp, payload)
                if result:
                    result.location = "FUZZ"
                    result.param = "(FUZZ)"
                    result.status_code = resp.status_code
                    results.append(result)
                    if self.logger:
                        self.logger.finding(result)

            self._log_summary(checker, results)
            return results

        # ── Normal mode (no FUZZ markers) ──────────────────────

        # Capture baseline once
        baseline_params, baseline_body = orig_params, orig_body
        if query_csrf or body_csrf:
            baseline_params, baseline_body = self._refresh_csrf(
                request, orig_params, orig_body if isinstance(orig_body, dict) else {},
                query_csrf, body_csrf,
            )
        baseline = self._capture_baseline(request, base_url, orig_headers, baseline_params, baseline_body)

        # Scan query parameters
        if orig_params:
            for param in orig_params:
                # Skip CSRF token fields — don't inject into them
                if param in query_csrf:
                    continue
                results += self._scan_injection_point(
                    checker, request, base_url, orig_headers,
                    orig_params, orig_body, baseline,
                    target="query", param_name=param,
                    query_csrf=query_csrf, body_csrf=body_csrf,
                )

        # Scan body parameters
        if orig_body and isinstance(orig_body, dict):
            for param in orig_body:
                # Skip CSRF token fields — don't inject into them
                if param in body_csrf:
                    continue
                results += self._scan_injection_point(
                    checker, request, base_url, orig_headers,
                    orig_params, orig_body, baseline,
                    target="form", param_name=param,
                    query_csrf=query_csrf, body_csrf=body_csrf,
                )

        self._log_summary(checker, results)
        return results

    # ── inject into one parameter ───────────────────────────────

    def _scan_injection_point(
        self, checker: BaseChecker, request: Request, url: str,
        headers: dict, params: dict, body, baseline: BaselineData,
        target: str, param_name: str,
        query_csrf: list | None = None, body_csrf: list | None = None,
    ) -> List[CheckResult]:
        results = []
        payloads = checker.get_payloads()
        total = len(payloads)
        query_csrf = query_csrf or []
        body_csrf = body_csrf or []
        has_csrf = bool(query_csrf or body_csrf)

        if self.logger:
            self.logger.debug(f"Testing {target}.{param_name} ({total} payloads)")

        for idx, payload in enumerate(payloads, 1):
            # Refresh CSRF tokens if needed
            cur_params = deepcopy(params)
            cur_body = deepcopy(body) if isinstance(body, dict) else body

            if has_csrf:
                cur_params, cur_body = self._refresh_csrf(
                    request, cur_params,
                    cur_body if isinstance(cur_body, dict) else {},
                    query_csrf, body_csrf,
                )

            if target == "query":
                cur_params[param_name] = payload
                resp = self._send(request, url, headers, cur_params, cur_body)
            else:  # form
                if isinstance(cur_body, dict):
                    cur_body[param_name] = payload
                resp = self._send(request, url, headers, cur_params, cur_body)

            if resp is None:
                continue

            if self.logger and self.logger.verbose >= 2:
                self.logger.debug(
                    f"  [{idx}/{total}] {target}.{param_name} = "
                    f"{self.logger.PAY}{payload}{Style.RESET_ALL}"
                )

            result = checker.check(baseline, resp, payload)
            if result:
                result.location = target
                result.param = param_name
                result.status_code = resp.status_code
                results.append(result)
                if self.logger:
                    self.logger.finding(result)

        return results

    # ── summary logging ─────────────────────────────────────────

    def _log_summary(self, checker: BaseChecker, results: List[CheckResult]):
        if not self.logger:
            return
        if results:
            self.logger.ok(f"{checker.name}: {len(results)} finding(s)")
        else:
            self.logger.fail(f"{checker.name}: no findings")
