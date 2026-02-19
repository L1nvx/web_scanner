"""Server-Side Template Injection checker — multi-engine, differential canary detection."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class SSTI(BaseChecker):

    name = "Server-Side Template Injection (SSTI)"

    def __init__(self):
        self.canary = self.rand(8)
        c = self.canary

        # Each tuple: (payload_template, expected_result_regex)
        # The canary goes before the expression so we can detect it
        # NOTE: Use string concatenation, NOT f-strings with ${} to avoid
        # Python evaluating template expressions at init time.
        self._tests = [
            # Jinja2, Twig — {{7*7}}
            (c + "{{7*7}}", re.compile(re.escape(c) + r"49")),
            # Jinja2 specific — {{'7'*7}}
            (c + "{{'7'*7}}", re.compile(re.escape(c) + r"7777777")),
            # Mako — ${7*7}
            (c + "${7*7}", re.compile(re.escape(c) + r"49")),
            # Smarty — {7*7}
            (c + "{7*7}", re.compile(re.escape(c) + r"49")),
            # Velocity — #set($x=7*7)$x
            (c + "#set($x=7*7)$x", re.compile(re.escape(c) + r"49")),
            # ERB (Ruby) — <%= 7*7 %>
            (c + "<%= 7*7 %>", re.compile(re.escape(c) + r"49")),
            # Pebble — {{7*7}}
            (c + "{{7*7}}", re.compile(re.escape(c) + r"49")),
            # Thymeleaf — ${7*7}
            (c + "${7*7}", re.compile(re.escape(c) + r"49")),
            # General expression — #{7*7}
            (c + "#{7*7}", re.compile(re.escape(c) + r"49")),
            # Angular-like — {{= 7*7 }}
            (c + "{{= 7*7 }}", re.compile(re.escape(c) + r"49")),
            # Razor — @(7*7)
            (c + "@(7*7)", re.compile(re.escape(c) + r"49")),
            # Jinja2 deeper — {{config}}
            (c + "{{config}}", re.compile(re.escape(c) + r"<Config")),
            # Jinja2 class traversal
            (c + "{{''.__class__}}", re.compile(re.escape(c) + r"<class 'str'>")),
        ]

    def get_payloads(self) -> List[str]:
        return [t[0] for t in self._tests]

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # Find which test corresponds to this payload
        for pay, rx in self._tests:
            if pay == payload:
                # Differential: pattern must NOT be in baseline but MUST be in injected
                if rx.search(body) and not rx.search(baseline.body):
                    return CheckResult(
                        vuln_name=self.name,
                        severity="critical",
                        confidence="confirmed",
                        location="", param="", payload=payload,
                        status_code=response.status_code,
                        evidence="Template expression evaluated: canary+result found",
                    )
                break

        return None
