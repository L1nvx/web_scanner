from typing import Dict
from urllib.parse import parse_qs, urlsplit
from os import path
import json


class Request:
    def __init__(self, requestFilename: str) -> None:
        """
        GET / HTTP/1.1
        Host: example.com
        Content-Type: xxx

        data=xxx
        """

        self.method = ""
        self.path = ""
        self.parameters = {}
        self.headers = {}
        self.body = {}

        self.requestFilename = requestFilename

    def parse(self) -> Dict:

        with open(self.requestFilename, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read().replace("\r\n", "\n")

        head, _, body_raw = raw.partition("\n\n")
        if not head.strip():
            raise ValueError("Request file is empty.")

        lines = [l for l in head.split("\n") if l.strip()]

        # Línea de petición: METHOD SP PATH [SP HTTP/x.y]
        parts0 = lines[0].split()
        if len(parts0) < 2:
            raise ValueError(f"Invalid request line: {lines[0]!r}")
        self.method = parts0[0]
        raw_path = parts0[1]

        # Separar path y query
        url_parts = urlsplit(raw_path)
        self.path = url_parts.path                      # sin query
        self.parameters = dict(
            parse_qs(url_parts.query, keep_blank_values=True))

        # Headers
        self.headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                self.headers[k.strip()] = v.strip()

        # Body
        self.body = {}
        ctype = self.headers.get("Content-Type", "").lower()
        body_raw = body_raw.strip()
        if body_raw:
            if "application/json" in ctype:
                try:
                    self.body = json.loads(body_raw)
                except Exception:
                    self.body = body_raw  # deja crudo si no es JSON válido
            elif "application/x-www-form-urlencoded" in ctype:
                self.body = dict(parse_qs(body_raw, keep_blank_values=True))
            else:
                self.body = body_raw

        # Host y limpieza de headers problemáticos
        self.host = self.headers.get('Host', self.headers.get('host', ''))
        self.headers.pop('Content-Length', None)

        return {
            'host': self.host,
            'method': self.method,
            'path': self.path,
            'parameters': self.parameters,
            'headers': self.headers,
            'body': self.body
        }

    # def parse(self) -> Dict:
    #     if not path.exists(self.requestFilename):
    #         raise FileNotFoundError(
    #             f"Request file '{self.requestFilename}' does not exist.")

    #     with open(self.requestFilename, 'r') as file:
    #         lines = file.readlines()

    #     if len(lines) == 0:
    #         raise ValueError("Request file is empty.")

    #     body_index = 0
    #     for i, line in enumerate(lines):
    #         if line.strip() == "":
    #             body_index = i
    #             break

    #     lines = [line.strip() for line in lines if line.strip()]
    #     # Get method
    #     self.method = lines[0].split()[0]

    #     # Get path
    #     self.path = lines[0].split()[1]

    #     # Get headers
    #     for line in lines[:body_index]:
    #         if ':' in line:
    #             key, value = line.split(':', 1)
    #             self.headers[key.strip()] = value.strip()
    #     # Get parameters
    #     if '?' in self.path:
    #         self.parameters = parse_qs(self.path.split('?', 1)[1])

    #     # Get body; JSON OR form-urlencoded
    #     if body_index > 0:
    #         body_data = ''.join([unquote(x) for x in lines[body_index:]])
    #         if '{' in body_data and '}' in body_data and ':' in body_data and '"' in body_data:
    #             try:
    #                 self.body = json.loads(body_data)
    #             except Exception as e:
    #                 print(e)
    #         else:
    #             if '=' in body_data:
    #                 self.body = parse_qs(body_data)
    #     self.host = self.headers.get('Host', '')
    #     return {
    #         'host': self.host,
    #         'method': self.method,
    #         'path': self.path,
    #         'parameters': self.parameters,
    #         'headers': self.headers,
    #         'body': self.body
    #     }

    def __str__(self) -> str:
        return f"Method: {self.method}\nPath: {self.path}\nHost: {self.host}\nParameters: {self.parameters}\nHeaders: {self.headers}\nBody: {self.body}"


if __name__ == '__main__':
    request = Request()
    try:
        request.parse('/tmp/example.req')
    except Exception as e:
        print(f"Error: {e}")
    else:
        print("Request parsed successfully.")
