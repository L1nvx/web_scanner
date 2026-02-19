"""Command Injection checker — differential echo + time-based detection."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class CMDi(BaseChecker):

    name = "Command Injection"

    def __init__(self, sleep_s: int = 5, time_margin: float = 2.0):
        self.sleep_s = sleep_s
        self.time_margin = time_margin
        self.canary = self.rand(10)

        c = self.canary
        s = self.sleep_s

        separators = [";", "|", "||", "&&"]
        unix_echo = [f"echo {c}", f"printf {c}"]
        unix_sleep = [f"sleep {s}", f"ping -c {s} 127.0.0.1"]
        win_echo = [f"echo {c}"]
        win_sleep = [f"timeout /T {s}", f"ping -n {s} 127.0.0.1 >NUL"]

        payloads = set()

        # Unix: echo (output-based)
        for cmd in unix_echo:
            for sep in separators:
                payloads.add(f"{sep}{cmd}")
            payloads.add(f"`{cmd}`")
            payloads.add(f"$({cmd})")
            payloads.add(f"\n{cmd}")

        # Unix: sleep (time-based)
        for cmd in unix_sleep:
            for sep in separators:
                payloads.add(f"{sep}{cmd}")
            payloads.add(f"`{cmd}`")
            payloads.add(f"$({cmd})")
            payloads.add(f"\n{cmd}")

        # Windows: echo
        for cmd in win_echo:
            for sep in separators:
                payloads.add(f"{sep}{cmd}")

        # Windows: sleep
        for cmd in win_sleep:
            for sep in separators:
                payloads.add(f"{sep}{cmd}")

        # Add variants with quote-closing prefixes
        quotes = ["'", '"', ")"]
        enriched = set()
        for p in payloads:
            enriched.add(p)
            for q in quotes:
                enriched.add(q + p)

        self.payloads_list = list(enriched)
        self._canary_rx = re.compile(re.escape(self.canary))

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # ── 1. Echo-based (differential): canary NOT in baseline, YES in injected ──
        if self._canary_rx.search(body) and not self._canary_rx.search(baseline.body):
            return CheckResult(
                vuln_name=self.name,
                severity="critical",
                confidence="confirmed",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence=f"Canary '{self.canary}' reflected in response",
            )

        # ── 2. Time-based (differential) ──
        try:
            elapsed = response.elapsed.total_seconds()
            threshold = baseline.elapsed + self.sleep_s - self.time_margin
            if threshold > 0 and elapsed >= threshold:
                return CheckResult(
                    vuln_name=self.name,
                    severity="high",
                    confidence="tentative",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Time: baseline={baseline.elapsed:.2f}s, injected={elapsed:.2f}s",
                )
        except Exception:
            pass

        return None
