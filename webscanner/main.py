import argparse
from webscanner.parsers.request import Request
from webscanner.core.engine import Engine
from webscanner.checkers.ssti import SSTI
from webscanner.checkers.sqli import SQLi
from webscanner.checkers.lfi import LFI
from webscanner.checkers.cmdi import CMDi
from webscanner.checkers.xss import XSS
from webscanner.reporters.console import Log


def main():
    p = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    p.add_argument("--proxy", help="Proxy (ej: http://127.0.0.1:8080)")
    p.add_argument("--request", required=True, help="Archivo de request raw")
    p.add_argument("--request-proto", default="https",
                   choices=["http", "https"])
    p.add_argument("-v", "--verbose", action="count", default=1,
                   help="-v, -vv")
    args = p.parse_args()

    req = Request(args.request)
    req.parse()
    log = Log(verbose=args.verbose)
    engine = Engine(proxy=args.proxy, protocol=args.request_proto, logger=log)

    checks = [SSTI(), XSS(), SQLi(), LFI(), CMDi()]
    for chk in checks:
        engine.scan(chk, req)


if __name__ == "__main__":
    main()
