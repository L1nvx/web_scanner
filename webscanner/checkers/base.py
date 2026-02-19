"""Abstract base for all vulnerability checkers."""

from abc import ABC, abstractmethod
from typing import Optional, List
import random
import string

import httpx

from webscanner.core.models import CheckResult, BaselineData


class BaseChecker(ABC):
    """Every checker must implement get_payloads() and check()."""

    name: str = "Unnamed Checker"

    # ── public API ──────────────────────────────────────────────

    @abstractmethod
    def get_payloads(self) -> List[str]:
        """Return the list of payloads to inject."""
        ...

    @abstractmethod
    def check(
        self,
        baseline: BaselineData,
        response: httpx.Response,
        payload: str,
    ) -> Optional[CheckResult]:
        """
        Compare *response* (injected) against *baseline* (clean).
        Return a CheckResult if a vulnerability was detected, else None.
        """
        ...

    # ── shared helpers ──────────────────────────────────────────

    @staticmethod
    def rand(n: int = 8) -> str:
        """Random alphanumeric canary string."""
        abc = string.ascii_letters + string.digits
        return "".join(random.choice(abc) for _ in range(n))
