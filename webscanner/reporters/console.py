"""Console reporter — coloured output with progress and summary."""

from colorama import init as colorama_init, Fore, Style
from datetime import datetime
from typing import List

from webscanner.core.models import CheckResult

colorama_init(autoreset=True)

# Severity → color map
_SEV_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.GREEN,
    "info": Fore.CYAN,
}

# Confidence → label
_CONF_LABEL = {
    "confirmed": f"{Fore.GREEN}confirmed{Style.RESET_ALL}",
    "firm": f"{Fore.YELLOW}firm{Style.RESET_ALL}",
    "tentative": f"{Fore.YELLOW}tentative{Style.RESET_ALL}",
}


class Log:
    def __init__(self, verbose: int = 1):
        self.verbose = verbose
        self.PAY = Fore.MAGENTA

    # ── formatting ─────────────────────────────────────────────

    @staticmethod
    def _time():
        return datetime.now().strftime("[%H:%M:%S]")

    def _fmt(self, level: str, color: str):
        return f"{self._time()} {color}[{level}]{Style.RESET_ALL}"

    # ── log levels ─────────────────────────────────────────────

    def info(self, msg: str):
        if self.verbose >= 1:
            print(f"{self._fmt('INFO', Fore.CYAN)} {msg}")

    def warn(self, msg: str):
        if self.verbose >= 0:
            print(f"{self._fmt('WARN', Fore.YELLOW)} {msg}")

    def ok(self, msg: str):
        print(f"{self._fmt('OK', Fore.GREEN)} {msg}")

    def fail(self, msg: str):
        print(f"{self._fmt('FAIL', Fore.RED)} {msg}")

    def debug(self, msg: str):
        if self.verbose >= 2:
            print(f"{self._fmt('DBG', Fore.MAGENTA)} {msg}")

    # ── finding ────────────────────────────────────────────────

    def finding(self, result: CheckResult):
        sev_col = _SEV_COLOR.get(result.severity, Fore.WHITE)
        conf = _CONF_LABEL.get(result.confidence, result.confidence)
        print(
            f"{self._fmt('VULN', sev_col)} "
            f"{Style.BRIGHT}{result.vuln_name}{Style.RESET_ALL} "
            f"[{conf}] "
            f"{result.location}.{result.param} = "
            f"{Fore.MAGENTA}{result.payload}{Style.RESET_ALL} "
            f"{Style.DIM}(HTTP {result.status_code}){Style.RESET_ALL}"
        )
        if result.evidence:
            print(f"         └─ {Style.DIM}{result.evidence}{Style.RESET_ALL}")

    # ── summary table ──────────────────────────────────────────

    def summary(self, all_results: List[CheckResult]):
        print()
        if not all_results:
            print(f"{Fore.GREEN}{Style.BRIGHT}No vulnerabilities found.{Style.RESET_ALL}")
            return

        print(f"{Fore.RED}{Style.BRIGHT}╔══ SCAN SUMMARY ═══════════════════════════════════╗{Style.RESET_ALL}")
        for r in all_results:
            sev_col = _SEV_COLOR.get(r.severity, Fore.WHITE)
            conf = _CONF_LABEL.get(r.confidence, r.confidence)
            print(
                f"  {sev_col}[{r.severity.upper()}]{Style.RESET_ALL} "
                f"{r.vuln_name} @ {r.location}.{r.param} "
                f"[{conf}]"
            )
            print(f"           payload: {Fore.MAGENTA}{r.payload}{Style.RESET_ALL}")
            if r.evidence:
                print(f"           evidence: {Style.DIM}{r.evidence}{Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"  Total: {Style.BRIGHT}{len(all_results)}{Style.RESET_ALL} finding(s)")
