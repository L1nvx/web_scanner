"""Shared data models for the web scanner."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CheckResult:
    """A single vulnerability finding."""
    vuln_name: str
    severity: str          # "critical", "high", "medium", "low", "info"
    confidence: str        # "confirmed", "tentative", "firm"
    location: str          # "query", "form", "path", "header", "FUZZ"
    param: str
    payload: str
    status_code: int
    evidence: str = ""     # Short proof snippet

    def __str__(self):
        return (f"[{self.severity.upper()}][{self.confidence}] {self.vuln_name} "
                f"@ {self.location}.{self.param} — payload={self.payload!r} "
                f"(HTTP {self.status_code})")


@dataclass
class BaselineData:
    """Captured data from a clean (payloadless) request."""
    status_code: int = 0
    body: str = ""
    body_length: int = 0
    elapsed: float = 0.0
    headers: dict = field(default_factory=dict)
