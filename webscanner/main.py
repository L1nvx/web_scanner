"""Web Scanner — CLI entry point."""

import argparse
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
{Style.RESET_ALL}{Style.DIM}  v2.2 — Differential Vulnerability Scanner{Style.RESET_ALL}
"""

# Available checkers
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


def _build_checkers(checks_arg: str) -> list:
    """Parse --checks argument and instantiate the selected checkers."""
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


def _scan_request(engine: Engine, checks: list, req: Request, log: Log) -> list:
    """Run all selected checkers against a single Request. Returns results."""
    log.info(f"Target: {req.method} {req.host}{req.path}")
    if req.parameters:
        log.info(f"  Query params: {', '.join(req.parameters.keys())}")
    if isinstance(req.body, dict) and req.body:
        log.info(f"  Body params:  {', '.join(req.body.keys())}")
    print()

    all_results = []
    for chk in checks:
        results = engine.scan(chk, req)
        all_results.extend(results)
    return all_results


def _detect_protocol(url: str) -> str:
    """Detect protocol from URL string."""
    if url.startswith("http://"):
        return "http"
    return "https"


def main():
    p = argparse.ArgumentParser(
        description="Web Vulnerability Scanner with differential detection",
    )

    # Input modes (mutually exclusive)
    input_group = p.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--request",
                             help="Raw request file (use FUZZ as injection marker)")
    input_group.add_argument("--url",
                             help="Target URL (e.g. http://example.com/?id=1)")

    # Protocol (only for --request mode)
    p.add_argument("--request-proto", default="https",
                   choices=["http", "https"],
                   help="Protocol for --request mode (default: https)")

    # Crawl options
    p.add_argument("--crawl", action="store_true",
                   help="Crawl the target URL to discover forms and links")
    p.add_argument("--crawl-depth", type=int, default=2,
                   help="Crawl recursion depth (default: 2)")

    # General options
    p.add_argument("--proxy",
                   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--checks", default="all",
                   help="Comma-separated checkers: sqli,xss,ssti,lfi,cmdi,ssrf,redirect,crlf or 'all'")
    p.add_argument("--timeout", type=int, default=15,
                   help="HTTP timeout in seconds (default: 15)")
    p.add_argument("-v", "--verbose", action="count", default=1,
                   help="Verbosity: -v (info), -vv (debug)")
    args = p.parse_args()

    print(BANNER)

    # Validate flags
    if args.crawl and not args.url:
        print(f"{Fore.RED}--crawl requires --url{Style.RESET_ALL}")
        sys.exit(1)

    # Logger & checkers
    log = Log(verbose=args.verbose)
    selected_names, checks = _build_checkers(args.checks)
    log.info(f"Checkers: {', '.join(selected_names)}")

    all_results = []

    # ── MODE 1: --request (file-based, original mode) ──────────
    if args.request:
        req = Request(args.request)
        req.parse()

        engine = Engine(
            proxy=args.proxy,
            protocol=args.request_proto,
            logger=log,
            timeout=args.timeout,
        )

        all_results = _scan_request(engine, checks, req, log)

    # ── MODE 2: --url (direct URL scan) ────────────────────────
    elif args.url:
        protocol = _detect_protocol(args.url)
        engine = Engine(
            proxy=args.proxy,
            protocol=protocol,
            logger=log,
            timeout=args.timeout,
        )

        if args.crawl:
            # ── CRAWL MODE ─────────────────────────────────────
            crawler = Crawler(
                client=engine.client,
                logger=log,
                max_depth=args.crawl_depth,
            )
            targets = crawler.crawl(args.url)

            if not targets:
                log.warn("No scannable targets found during crawl")
            else:
                log.info(f"Scanning {len(targets)} discovered target(s)...")
                print()

                for i, req in enumerate(targets, 1):
                    print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")
                    log.info(f"Target {i}/{len(targets)}")
                    results = _scan_request(engine, checks, req, log)
                    all_results.extend(results)
                    print()

        else:
            # ── DIRECT URL MODE ────────────────────────────────
            req = Request.from_url(args.url, method="GET")

            if not req.parameters:
                log.warn(
                    "No query parameters found in URL. "
                    "Use --crawl to discover forms, or add ?param=value"
                )

            all_results = _scan_request(engine, checks, req, log)

    # ── Summary ────────────────────────────────────────────────
    log.summary(all_results)


if __name__ == "__main__":
    main()
