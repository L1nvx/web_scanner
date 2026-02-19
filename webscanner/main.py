"""Web Scanner — async CLI entry point."""

import argparse
import asyncio
import sys

from colorama import Fore, Style

from webscanner.parsers.request import Request
from webscanner.core.engine import Engine
from webscanner.core.crawler import Crawler
from webscanner.checkers.ssti import SSTI
from webscanner.checkers.sqli import SQLi
from webscanner.checkers.lfi import LFI
from webscanner.checkers.cmdi import CMDi
from webscanner.checkers.xss import XSS
from webscanner.checkers.ssrf import SSRF
from webscanner.checkers.open_redirect import OpenRedirect
from webscanner.checkers.header_injection import HeaderInjection
from webscanner.reporters.console import Log

BANNER = f"""
{Fore.RED}{Style.BRIGHT}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██╗██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}{Style.DIM}  v2.3 — Async Differential Vulnerability Scanner{Style.RESET_ALL}
"""

CHECKERS = {
    "sqli": SQLi,
    "ssti": SSTI,
    "xss": XSS,
    "lfi": LFI,
    "cmdi": CMDi,
    "ssrf": SSRF,
    "redirect": OpenRedirect,
    "crlf": HeaderInjection,
}


def _build_checkers(checks_arg: str) -> tuple:
    if checks_arg == "all":
        selected = list(CHECKERS.keys())
    else:
        selected = [c.strip().lower() for c in checks_arg.split(",")]
        invalid = [c for c in selected if c not in CHECKERS]
        if invalid:
            print(f"{Fore.RED}Unknown checkers: {', '.join(invalid)}{Style.RESET_ALL}")
            print(f"Available: {', '.join(CHECKERS.keys())}")
            sys.exit(1)
    return selected, [CHECKERS[name]() for name in selected]


async def _scan_request(engine: Engine, checks: list, req: Request, log: Log) -> list:
    """Run all selected checkers against a single Request. Returns results."""
    log.info(f"Target: {req.method} {req.host}{req.path}")
    if req.parameters:
        log.info(f"  Query params: {', '.join(req.parameters.keys())}")
    if isinstance(req.body, dict) and req.body:
        log.info(f"  Body params:  {', '.join(req.body.keys())}")
    print()

    all_results = []
    for chk in checks:
        results = await engine.scan(chk, req)
        all_results.extend(results)
    return all_results


def _detect_protocol(url: str) -> str:
    if url.startswith("http://"):
        return "http"
    return "https"


async def async_main(args):
    log = Log(verbose=args.verbose)
    selected_names, checks = _build_checkers(args.checks)
    log.info(f"Checkers: {', '.join(selected_names)}")

    concurrency = getattr(args, "threads", 15)
    all_results = []

    if args.request:
        req = Request(args.request)
        req.parse()
        engine = Engine(
            proxy=args.proxy, protocol=args.request_proto,
            logger=log, timeout=args.timeout, concurrency=concurrency,
        )
        try:
            all_results = await _scan_request(engine, checks, req, log)
        finally:
            await engine.close()

    elif args.url:
        protocol = _detect_protocol(args.url)
        engine = Engine(
            proxy=args.proxy, protocol=protocol,
            logger=log, timeout=args.timeout, concurrency=concurrency,
        )

        try:
            if args.crawl:
                crawler = Crawler(
                    client=engine.client, logger=log,
                    max_depth=args.crawl_depth, concurrency=concurrency,
                )
                targets = await crawler.crawl(args.url)

                if not targets:
                    log.warn("No scannable targets found during crawl")
                else:
                    log.info(f"Scanning {len(targets)} discovered target(s)...")
                    print()

                    for i, req in enumerate(targets, 1):
                        print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")
                        log.info(f"Target {i}/{len(targets)}")
                        results = await _scan_request(engine, checks, req, log)
                        all_results.extend(results)
                        print()
            else:
                req = Request.from_url(args.url, method="GET")
                if not req.parameters:
                    log.warn(
                        "No query parameters found in URL. "
                        "Use --crawl to discover forms, or add ?param=value"
                    )
                all_results = await _scan_request(engine, checks, req, log)
        finally:
            await engine.close()

    log.summary(all_results)


def main():
    p = argparse.ArgumentParser(
        description="Async Web Vulnerability Scanner with differential detection",
    )

    input_group = p.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--request", help="Raw request file (FUZZ as injection marker)")
    input_group.add_argument("--url", help="Target URL (e.g. http://example.com/?id=1)")

    p.add_argument("--request-proto", default="https", choices=["http", "https"],
                   help="Protocol for --request mode (default: https)")
    p.add_argument("--crawl", action="store_true", help="Crawl to discover forms and links")
    p.add_argument("--crawl-depth", type=int, default=2, help="Crawl depth (default: 2)")
    p.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--checks", default="all",
                   help="Checkers: sqli,xss,ssti,lfi,cmdi,ssrf,redirect,crlf or 'all'")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout (default: 15)")
    p.add_argument("--threads", type=int, default=15,
                   help="Max concurrent requests (default: 15)")
    p.add_argument("-v", "--verbose", action="count", default=1, help="-v info, -vv debug")

    args = p.parse_args()

    print(BANNER)

    if args.crawl and not args.url:
        print(f"{Fore.RED}--crawl requires --url{Style.RESET_ALL}")
        sys.exit(1)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
