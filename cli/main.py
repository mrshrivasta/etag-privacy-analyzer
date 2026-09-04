#!/usr/bin/env python3
"""
ETag Privacy Analyzer — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Sends a REAL HTTP GET request to the URL you provide. Only
scan URLs/systems you own or are explicitly authorized to test. Provided
AS IS, no warranty. See README.md for the full disclaimer.

Usage:
    python3 cli/main.py scan https://example.com
    python3 cli/main.py scan https://example.com --json
    python3 cli/main.py scan https://example.com --csv findings.csv
    python3 cli/main.py rules
"""
import argparse
import csv
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 ETag Privacy Analyzer (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"


def cmd_scan(args):
    print(BANNER)
    print(f"Requesting: {args.url}\n")

    engine = ScanEngine(args.url, timeout=args.timeout, verify_tls=not args.no_verify_tls)
    result = engine.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    if result["response"]:
        print(f"Status code : {result['response']['status_code']}")
        print(f"Final URL   : {result['response']['url']}")
        print(f"Elapsed     : {result['response']['elapsed_ms']}ms")
    print(f"Errors      : {result['errors_count']}")
    print(f"Findings    : {len(result['findings'])}\n")

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"{color}[{f['severity'].upper():8}]{RESET} {f['rule_id']} {f['rule_name']}")
        print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "url", "status_code", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    if result["findings"]:
        sys.exit(1)
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="epa-cli",
        description="ETag Privacy Analyzer — real HTTP ETag privacy & information-disclosure auditor (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a real URL's ETag header for privacy risks")
    scan_p.add_argument("url", help="Target URL (you must be authorized to test it)")
    scan_p.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds")
    scan_p.add_argument("--no-verify-tls", action="store_true", help="Disable TLS certificate verification")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV file")
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
