"""Header Injection / CRLF checker — differential detection of injected response headers."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class HeaderInjection(BaseChecker):

    name = "Header Injection / CRLF"

    def __init__(self):
        self.canary = self.rand(8)
        c = self.canary

        # Injected header name to look for
        self._injected_header = f"X-Injected-{c}"

        self.payloads_list = [
            # Raw CRLF
            f"\r\n{self._injected_header}: true",
            f"\r\nX-Test: {c}",
            # URL-encoded CRLF
            f"%0d%0a{self._injected_header}: true",
            f"%0d%0aX-Test: {c}",
            # Double-encoded
            f"%250d%250a{self._injected_header}: true",
            # Only LF (some servers accept)
            f"%0a{self._injected_header}: true",
            f"\n{self._injected_header}: true",
            # Unicode variants
            f"%E5%98%8A%E5%98%8D{self._injected_header}: true",
            # Inject Set-Cookie
            f"\r\nSet-Cookie: injected={c}",
            f"%0d%0aSet-Cookie: injected={c}",
            # HTTP response splitting
            f"\r\n\r\n<html>{c}</html>",
            f"%0d%0a%0d%0a<html>{c}</html>",
        ]

        self._canary_rx = re.compile(re.escape(c))

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        resp_headers = dict(response.headers)
        base_headers = baseline.headers or {}

        # 1. Check if injected header appeared
        for header_name, header_value in resp_headers.items():
            lower_name = header_name.lower()

            # Check for our injected header
            if "x-injected" in lower_name or "x-test" in lower_name:
                # Must NOT exist in baseline
                if lower_name not in {k.lower() for k in base_headers}:
                    return CheckResult(
                        vuln_name=self.name,
                        severity="high",
                        confidence="confirmed",
                        location="", param="", payload=payload,
                        status_code=response.status_code,
                        evidence=f"Injected header found: {header_name}: {header_value[:60]}",
                    )

            # Check for injected Set-Cookie
            if lower_name == "set-cookie" and self.canary in str(header_value):
                if "set-cookie" not in {k.lower() for k in base_headers}:
                    return CheckResult(
                        vuln_name=self.name,
                        severity="high",
                        confidence="confirmed",
                        location="", param="", payload=payload,
                        status_code=response.status_code,
                        evidence=f"Injected Set-Cookie: {header_value[:60]}",
                    )

        # 2. Check if canary appears in response body (response splitting)
        body = response.text or ""
        if self._canary_rx.search(body) and not self._canary_rx.search(baseline.body):
            # Only flag if the canary is in an HTML context we injected
            if f"<html>{self.canary}</html>" in body:
                return CheckResult(
                    vuln_name=self.name,
                    severity="critical",
                    confidence="confirmed",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence="HTTP response splitting: injected HTML in body",
                )

        # 3. Check if X-Custom-Language header got corrupted (contains CRLF chars)
        for header_name, header_value in resp_headers.items():
            if self.canary in str(header_value) and self.canary not in str(base_headers.get(header_name, "")):
                return CheckResult(
                    vuln_name=self.name,
                    severity="medium",
                    confidence="tentative",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Canary reflected in header: {header_name}",
                )

        return None
