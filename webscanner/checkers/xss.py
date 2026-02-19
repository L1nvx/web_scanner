"""Reflected XSS checker — differential canary reflection detection."""

import re
from html import unescape
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class XSS(BaseChecker):

    name = "Cross-Site Scripting (Reflected XSS)"

    def __init__(self):
        self.canary = self.rand(10)
        c = self.canary

        self.payloads_list = [
            # Break out of text context
            f"{c}<script>alert(1)</script>",
            f'{c}"><svg/onload=alert(1)>',
            f"{c}'><img src=x onerror=alert(1)>",
            # Break out of tag context
            f"{c}</title><svg/onload=alert(1)>",
            f"{c}</textarea><script>alert(1)</script>",
            # Break out of HTML comment
            f"{c}--><svg/onload=alert(1)>",
            # Break out of script context
            f"{c}</script><script>alert(1)</script>",
            # Attribute context
            f'{c}"><body onfocus=alert(1) autofocus>',
            f"{c}' autofocus onfocus=alert(1) x='",
            # Template literal context
            f"{c}`-alert(1)-`",
            # Event handler via IMG
            f'{c}"><img src=x onerror=alert(1)//>',
        ]

        # Regex for the injected canary appearing alongside unescaped dangerous chars
        self._canary_rx = re.compile(re.escape(self.canary))

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # 1. Canary must NOT be in baseline (proves it's reflected, not pre-existing)
        if self._canary_rx.search(baseline.body):
            return None

        # 2. Canary must be present in the injected response
        if not self._canary_rx.search(body):
            return None

        # 3. Check if reflection is unescaped (dangerous)
        if self._is_unescaped_reflection(body, payload):
            return CheckResult(
                vuln_name=self.name,
                severity="high",
                confidence="confirmed",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence="Payload reflected unescaped in response",
            )

        # 4. Canary reflected but possibly escaped — lower confidence
        if self._has_partial_reflection(body):
            return CheckResult(
                vuln_name=self.name,
                severity="medium",
                confidence="tentative",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence="Canary reflected (possibly escaped)",
            )

        return None

    def _is_unescaped_reflection(self, body: str, payload: str) -> bool:
        """Check if the EXACT payload appears in the body without HTML-encoding."""
        # The full payload (canary + dangerous chars) must appear as-is
        if payload in body:
            return True

        # Check for common dangerous fragments near the canary
        c = self.canary
        danger = [
            f"{c}<script",
            f"{c}<svg",
            f"{c}<img",
            f"{c}</script>",
            f"{c}</title>",
            f"{c}</textarea>",
            f'{c}">',
            f"{c}'>",
        ]
        body_lower = body.lower()
        for d in danger:
            if d.lower() in body_lower:
                return True

        return False

    def _has_partial_reflection(self, body: str) -> bool:
        """Canary is present but we couldn't confirm unescaped injection."""
        # Check if entities are used around canary (signs of escaping)
        idx = body.find(self.canary)
        if idx < 0:
            return False
        # Look at the 200 chars after the canary
        snippet = body[idx:idx + 200]
        # If snippet contains raw < or > near canary, could be dangerous
        if "<" in snippet or ">" in snippet:
            return True
        return False
