from webscanner.parsers.request import Request
import httpx
from copy import deepcopy
from typing import List, Dict, Any
from colorama import Style

_STOP_HDRS = {"host", "content-length",
              "transfer-encoding", "content-encoding"}


class Engine:
    def __init__(self, proxy: str | None = None, protocol: str = "https", logger=None):
        self.name = "WebScanner"
        self.version = "1.0.0"
        self.protocol = protocol
        self.logger = logger
        self.client = httpx.Client(
            verify=False, proxy=proxy, follow_redirects=True, timeout=10)

    def _host(self, req: Request) -> str:
        host = getattr(req, "host", "") or req.headers.get(
            "Host") or req.headers.get("host", "")
        if not host:
            raise ValueError("Host no definido en la request.")
        return host

    # ---------- FUZZ helpers ----------
    @staticmethod
    def _has_fuzz_in_params(params: dict) -> bool:
        if not isinstance(params, dict):
            return False
        for v in params.values():
            if isinstance(v, list) and any(isinstance(x, str) and "FUZZ" in x for x in v):
                return True
            if isinstance(v, str) and "FUZZ" in v:
                return True
        return False

    @staticmethod
    def _apply_fuzz_params(params: dict, payload: str) -> dict:
        mp = deepcopy(params)
        for k, v in list(mp.items()):
            if isinstance(v, list):
                mp[k] = [x.replace("FUZZ", payload) if isinstance(
                    x, str) else x for x in v]
            elif isinstance(v, str):
                mp[k] = v.replace("FUZZ", payload)
        return mp

    @staticmethod
    def _has_fuzz_in_headers(headers: dict) -> bool:
        for k, v in headers.items():
            if k.lower() in _STOP_HDRS:
                continue
            if isinstance(v, str) and "FUZZ" in v:
                return True
        return False

    @staticmethod
    def _apply_fuzz_headers(headers: dict, payload: str) -> dict:
        mh = deepcopy(headers)
        for k in list(mh):
            if k.lower() in _STOP_HDRS:
                mh.pop(k, None)
        for k, v in list(mh.items()):
            if isinstance(v, str):
                mh[k] = v.replace("FUZZ", payload)
        return mh

    @staticmethod
    def _has_fuzz_in_body(body) -> bool:
        if isinstance(body, dict):
            for v in body.values():
                if isinstance(v, list) and any(isinstance(x, str) and "FUZZ" in x for x in v):
                    return True
                if isinstance(v, str) and "FUZZ" in v:
                    return True
        elif isinstance(body, str):
            return "FUZZ" in body
        return False

    @staticmethod
    def _apply_fuzz_body(body, payload: str):
        if isinstance(body, dict):
            mb = deepcopy(body)
            for k, v in list(mb.items()):
                if isinstance(v, list):
                    mb[k] = [x.replace("FUZZ", payload) if isinstance(
                        x, str) else x for x in v]
                elif isinstance(v, str):
                    mb[k] = v.replace("FUZZ", payload)
            return mb
        elif isinstance(body, str):
            return body.replace("FUZZ", payload)
        return body
    # -----------------------------------

    def _send(self, request: Request, url: str, headers: dict, params: dict | None, body) -> httpx.Response:
        is_json = "application/json" in (
            request.headers.get("Content-Type", "") or "").lower()
        if is_json and isinstance(body, dict):
            return self.client.request(method=request.method, url=url, headers=headers, params=params or None, json=body)
        else:
            return self.client.request(method=request.method, url=url, headers=headers, params=params or None,
                                       data=body if body else None)

    def scan(self, vuln: object, request: Request) -> List[Dict[str, Any]]:
        payloads = vuln.get_payloads()
        results: List[Dict[str, Any]] = []

        host = self._host(request)
        base_path = request.path if request.path.startswith(
            "/") else f"/{request.path}"
        orig_params = deepcopy(request.parameters) if isinstance(
            request.parameters, dict) else {}
        orig_body = deepcopy(request.body) if isinstance(
            request.body, (dict, str)) else {}
        orig_headers = deepcopy(request.headers) if isinstance(
            request.headers, dict) else {}

        # Detecta modo FUZZ
        fuzz_in_path = isinstance(base_path, str) and "FUZZ" in base_path
        fuzz_in_params = self._has_fuzz_in_params(orig_params)
        fuzz_in_body = self._has_fuzz_in_body(orig_body)
        fuzz_in_headers = self._has_fuzz_in_headers(orig_headers)
        fuzz_mode = fuzz_in_path or fuzz_in_params or fuzz_in_body or fuzz_in_headers

        if self.logger:
            url_preview = f"{self.protocol}://{host}{base_path}"
            self.logger.info(f"Escaneando {vuln.name} en {url_preview}")
            if fuzz_mode and self.logger.verbose >= 2:
                self.logger.debug(
                    "Modo FUZZ activado (solo se mutarán posiciones con 'FUZZ').")

        # ---------- MODO FUZZ ----------
        if fuzz_mode:
            for payload in payloads:
                path_mut = base_path.replace(
                    "FUZZ", payload) if fuzz_in_path else base_path
                url = f"{self.protocol}://{host}{path_mut}"
                params_mut = self._apply_fuzz_params(
                    orig_params, payload) if fuzz_in_params else orig_params
                body_mut = self._apply_fuzz_body(
                    orig_body, payload) if fuzz_in_body else orig_body
                headers_mut = self._apply_fuzz_headers(
                    orig_headers, payload) if fuzz_in_headers else orig_headers

                if self.logger and self.logger.verbose >= 2:
                    self.logger.debug(f"→ {request.method} {url}")
                    if fuzz_in_params:
                        self.logger.debug(
                            f"  params FUZZ = {self.logger.PAY}{payload}{Style.RESET_ALL}")
                    if fuzz_in_body:
                        self.logger.debug(
                            f"  body   FUZZ = {self.logger.PAY}{payload}{Style.RESET_ALL}")
                    if fuzz_in_headers:
                        self.logger.debug(
                            f"  header FUZZ = {self.logger.PAY}{payload}{Style.RESET_ALL}")

                resp = self._send(request, url, headers_mut,
                                  params_mut, body_mut)

                if vuln.check_response(resp):
                    results.append({
                        "severity": "high", "vulnerability": vuln.name,
                        "location": "FUZZ", "param": "(path/param/body/header)",
                        "payload": payload, "status_code": resp.status_code,
                    })
                    if self.logger:
                        self.logger.finding(
                            "high", vuln.name, "FUZZ", "(mixed)", payload, resp.status_code)

            if self.logger and not results:
                self.logger.fail(f"Sin hallazgos para {vuln.name}")
            return results

        # ---------- MODO NORMAL sin FUZZ ----------
        base_url = f"{self.protocol}://{host}{base_path}"

        # QUERY
        if orig_params:
            for param, _ in orig_params.items():
                if self.logger:
                    self.logger.debug(f"Param query: {param}")
                mutated_params = deepcopy(orig_params)
                for payload in payloads:
                    mutated_params[param] = [payload]
                    if self.logger and self.logger.verbose >= 2:
                        self.logger.debug(
                            f"→ GET {param}={self.logger.PAY}{payload}{Style.RESET_ALL}")
                    resp = self._send(request, base_url,
                                      orig_headers, mutated_params, orig_body)
                    if vuln.check_response(resp):
                        results.append({
                            "severity": "high", "vulnerability": vuln.name,
                            "location": "query", "param": param, "payload": payload,
                            "status_code": resp.status_code,
                        })
                        if self.logger:
                            self.logger.finding(
                                "high", vuln.name, "query", param, payload, resp.status_code)

        # FORM / BODY
        if orig_body and isinstance(orig_body, dict):
            for param, _ in orig_body.items():
                if self.logger:
                    self.logger.debug(f"Param form: {param}")
                mutated_body = deepcopy(orig_body)
                for payload in payloads:
                    mutated_body[param] = [payload]
                    if self.logger and self.logger.verbose >= 2:
                        self.logger.debug(
                            f"→ POST {param}={self.logger.PAY}{payload}{Style.RESET_ALL}")
                    resp = self._send(request, base_url,
                                      orig_headers, orig_params, mutated_body)
                    if vuln.check_response(resp):
                        results.append({
                            "severity": "high", "vulnerability": vuln.name,
                            "location": "form", "param": param, "payload": payload,
                            "status_code": resp.status_code,
                        })
                        if self.logger:
                            self.logger.finding(
                                "high", vuln.name, "form", param, payload, resp.status_code)

        if self.logger and not results:
            self.logger.fail(f"Sin hallazgos para {vuln.name}")
        return results
