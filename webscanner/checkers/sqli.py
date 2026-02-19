"""SQL Injection checker — error-based + time-based with differential detection."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class SQLi(BaseChecker):

    name = "SQL Injection"

    def __init__(self, sleep_s: int = 5, time_margin: float = 2.0):
        self.sleep_s = sleep_s
        self.time_margin = time_margin   # injected.elapsed >= baseline.elapsed + sleep_s - margin

        s = self.sleep_s
        self.payloads_list = [
            # ── Error-based probes ──
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1-- -",
            '" OR 1=1-- -',
            "1' ORDER BY 1-- -",
            '1" ORDER BY 1-- -',
            "') OR ('1'='1",
            "1 UNION SELECT NULL-- -",

            # ── Time-based: MySQL ──
            f"' OR SLEEP({s})-- -",
            f'" OR SLEEP({s})-- -',
            f"' AND IF(1=1,SLEEP({s}),0)-- -",
            f'" AND IF(1=1,SLEEP({s}),0)-- -',
            f"1' AND SLEEP({s})-- -",

            # ── Time-based: PostgreSQL ──
            f"' OR pg_sleep({s})-- -",
            f'" OR pg_sleep({s})-- -',
            f"'; SELECT pg_sleep({s})-- -",

            # ── Time-based: MSSQL ──
            f"'; WAITFOR DELAY '0:0:{s}'-- -",
            f'"; WAITFOR DELAY \'0:0:{s}\'-- -',

            # ── Time-based: Oracle ──
            f"' AND DBMS_LOCK.SLEEP({s})-- -",

            # ── Time-based: SQLite ──
            "' AND randomblob(200000000)-- -",
            '" AND randomblob(200000000)-- -',
        ]

        # Error regex patterns — only real SQL errors
        self._err_patterns = [
            # MySQL / MariaDB
            re.compile(r"You have an error in your SQL syntax", re.I),
            re.compile(r"SQL syntax.*MySQL", re.I),
            re.compile(r"Warning.*\bmysql_", re.I),
            re.compile(r"Unknown column.*in.*field list", re.I),
            re.compile(r"Table '.*' doesn't exist", re.I),
            # PostgreSQL
            re.compile(r"PostgreSQL.*ERROR", re.I),
            re.compile(r"syntax error at or near", re.I),
            re.compile(r'relation ".*" does not exist', re.I),
            # MSSQL
            re.compile(r"Unclosed quotation mark after the character string", re.I),
            re.compile(r"Incorrect syntax near", re.I),
            re.compile(r"\bODBC\b.*\bSQL Server\b", re.I),
            # Oracle
            re.compile(r"ORA-\d{4,5}:", re.I),
            # SQLite
            re.compile(r"SQLite.*error", re.I),
            re.compile(r"\bno such table\b", re.I),
            # ORM / Generic
            re.compile(r"PDOException", re.I),
            re.compile(r"SQLSTATE\[\w+\]", re.I),
            re.compile(r"QueryException", re.I),
        ]

    def get_payloads(self) -> List[str]:
        return self.payloads_list

    def check(self, baseline: BaselineData, response: httpx.Response, payload: str) -> Optional[CheckResult]:
        body = response.text or ""

        # ── 1. Error-based (differential): error NOT in baseline, YES in injected ──
        for rx in self._err_patterns:
            if rx.search(body) and not rx.search(baseline.body):
                return CheckResult(
                    vuln_name=self.name,
                    severity="high",
                    confidence="confirmed",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"SQL error: {rx.pattern[:60]}",
                )

        # ── 2. Status-code flip (200 → 500) ──
        if baseline.status_code < 400 and response.status_code >= 500:
            return CheckResult(
                vuln_name=self.name,
                severity="high",
                confidence="tentative",
                location="", param="", payload=payload,
                status_code=response.status_code,
                evidence=f"Status flip {baseline.status_code} → {response.status_code}",
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
