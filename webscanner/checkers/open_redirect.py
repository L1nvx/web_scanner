"""Open Redirect checker — differential redirect detection."""

from typing import Optional, List
from urllib.parse import urlsplit

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


# Known external domains used in payloads
_EXTERNAL_DOMAINS = {"evil.com", "attacker.com", "example.com"}


class OpenRedirect(BaseChecker):

    name = "Open Redirect"

    def __init__(self):
        self.payloads_list = [
            # Protocol-relative
            "//evil.com",
            "//evil.com/",
            "///evil.com",
            # Full URL
            "https://evil.com",
            "https://evil.com/",
            "http://evil.com",
            # Backslash trick
            "/\\evil.com",
            "\\/evil.com",
            # Encoded variants
            "//evil%2ecom",
            "%2f%2fevil.com",
            # @ trick
            "http://vulnlab@evil.com",
            # Data URL
            "data:text/html,<script>alert(1)</script>",
            # Javascript protocol
            "javascript:alert(1)",
            # Null byte
            "//evil.com%00.vulnlab.local",
            # Tab/newline bypass
            "//evil.com%09",
            # CRLF in redirect
            "//evil.com%0d%0a",
        ]

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        # Check the final response and all redirect history
        # httpx with follow_redirects=True stores history in response.history

        # Check Location headers in redirect responses
        for hist_resp in getattr(response, "history", []):
            location = hist_resp.headers.get("location", "")
            if self._is_external_redirect(location):
                return CheckResult(
                    vuln_name=self.name,
                    severity="medium",
                    confidence="confirmed",
                    location="", param="", payload=payload,
                    status_code=hist_resp.status_code,
                    evidence=f"External redirect to: {location[:80]}",
                )

        # Also check if current response itself has a redirect Location
        location = response.headers.get("location", "")
        if location and self._is_external_redirect(location):
            return CheckResult(
                vuln_name=self.name,
                severity="medium",
                confidence="confirmed",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence=f"External redirect to: {location[:80]}",
            )

        # Check if response is a 3xx that wasn't in baseline
        if (300 <= response.status_code < 400 and
                not (300 <= baseline.status_code < 400)):
            return CheckResult(
                vuln_name=self.name,
                severity="low",
                confidence="tentative",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence=f"Status changed to redirect: {baseline.status_code}→{response.status_code}",
            )

        return None

    @staticmethod
    def _is_external_redirect(location: str) -> bool:
        """Check if the Location header points to an external domain."""
        if not location:
            return False

        # Protocol-relative URLs
        if location.startswith("//"):
            location = "https:" + location

        # Dangerous protocols
        lower = location.lower().strip()
        if lower.startswith(("javascript:", "data:", "vbscript:")):
            return True

        parts = urlsplit(location)
        if parts.hostname:
            hostname = parts.hostname.lower()
            # Check against known external test domains
            if hostname in _EXTERNAL_DOMAINS:
                return True
            # Any non-localhost external domain
            if hostname not in ("", "localhost", "127.0.0.1", "0.0.0.0", "::1"):
                # If the redirect goes to a totally different host, suspicious
                return True

        return False
