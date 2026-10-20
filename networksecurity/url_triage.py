"""Passive URL structure checks for analyst triage. Never opens a URL."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlsplit


REDIRECT_PARAMS = {"continue", "dest", "destination", "next", "redirect", "redirect_uri", "target", "url"}
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")


def inspect_url(value: str, line_number: int) -> dict:
    """Return signals without retaining the URL path, query values, or userinfo."""
    flags = []

    def flag(code: str, severity: str, detail: str) -> None:
        flags.append({"code": code, "severity": severity, "detail": detail})

    try:
        parsed = urlsplit(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".").encode("idna").decode("ascii")
        _ = parsed.port  # Reject malformed ports without retaining them.
        if not host:
            raise ValueError("missing or invalid host")
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("only HTTP and HTTPS URLs are supported")
        if len(host) > 253:
            raise ValueError("hostname is too long")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not DOMAIN.fullmatch(host):
                raise ValueError("invalid hostname")
    except (ValueError, UnicodeError):
        return {"line": line_number, "host": "", "flags": [
            {"code": "invalid-url", "severity": "review", "detail": "Not a valid HTTP(S) URL."}
        ]}

    if parsed.scheme.lower() == "http":
        flag("plain-http", "review", "The link uses HTTP rather than HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        flag("userinfo", "review", "The link includes userinfo before the host, which can obscure the destination.")
    try:
        ipaddress.ip_address(host)
        flag("ip-host", "review", "The link uses an IP address instead of a domain name.")
    except ValueError:
        pass
    if any(label.startswith("xn--") for label in host.split(".")):
        flag("punycode-host", "review", "The domain contains an internationalized punycode label.")
    if len(value) > 200:
        flag("long-url", "review", "The URL is longer than 200 characters.")
    parameter_names = set()
    for name, parameter_value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() in REDIRECT_PARAMS and parameter_value.lower().startswith(("http://", "https://")):
            parameter_names.add(name.lower())
    if parameter_names:
        flag("nested-destination", "review", "A query parameter contains another HTTP(S) destination.")
    return {"line": line_number, "host": host, "flags": flags}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, passive URL structure triage")
    parser.add_argument("--input", type=Path, required=True, help="UTF-8 text file, one URL per line")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized JSON report")
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 1024 * 1024:
            raise ValueError("Input exceeds the 1 MiB limit")
        records = []
        for number, raw_url in enumerate(args.input.read_text(encoding="utf-8").splitlines(), start=1):
            if raw_url.strip():
                records.append(inspect_url(raw_url, number))
        report = {"tool": "offline-url-triage", "urls_checked": len(records), "results": records,
                  "note": "Heuristic review signals only; no URLs were opened or classified as safe."}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {len(records)} URL reviews to {args.output}")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"url-triage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
