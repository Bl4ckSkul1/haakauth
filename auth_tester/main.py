"""
main.py — CLI orchestrator for HaakAuth.
Parses arguments, initializes modules, runs tests, generates reports.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from .colors import (
    banner, section, msg_info, msg_ok, msg_fail, msg_warn, msg_vuln,
    table_header, table_row, status_code_color,
    VERDE, ROJO, AMARILLO, CIAN, GRIS, NEGRITA, NARANJA, AZUL, RESET,
)
from .core import AuthTester, parse_cookies, parse_token
from .request_parser import parse_request_file
from .modules import ALL_MODULES


# ── Severity ordering ─────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLORS = {
    "critical": ROJO + NEGRITA,
    "high":     NARANJA + NEGRITA,
    "medium":   AMARILLO + NEGRITA,
    "low":      VERDE,
    "info":     AZUL,
}


# ── Argument parsing ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haakauth",
        description="HaakAuth — Authentication & Authorization Security Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  haakauth -u https://api.example.com/user/123 -t 'Bearer eyJ...'\n"
            "  haakauth -p burp_request.txt --all --proxy http://127.0.0.1:8080\n"
            "  haakauth -u https://api.example.com/orders/99 --idor --token2 'Bearer eyJ2...'\n"
            "  haakauth -u https://login.example.com --rate-limit --wordlist users.txt\n"
        ),
    )

    # ── Target ────────────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-u", "--url",      help="Target URL")
    target_group.add_argument("-p", "--peticion",  help="Burp Suite raw request file")

    # ── Authentication ────────────────────────────────────────────────────────
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-t", "--token",   help="Auth token (Bearer, Basic, or raw)")
    auth_group.add_argument("-c", "--cookie",  help="Session cookie(s) (e.g. 'session=abc; user=xyz')")
    auth_group.add_argument(
        "-H", "--header",
        action="append",
        metavar="HEADER",
        help="Custom header in 'Name: Value' format (repeatable)",
    )

    # ── Second account (IDOR) ─────────────────────────────────────────────────
    idor_group = parser.add_argument_group("Second Account (IDOR cross-account testing)")
    idor_group.add_argument("--token2",  help="Second account token")
    idor_group.add_argument("--cookie2", help="Second account cookie")

    # ── Module selection ──────────────────────────────────────────────────────
    mod_group = parser.add_argument_group("Module selection")
    mod_group.add_argument(
        "--modules",
        help="Comma-separated modules: jwt,idor,bypass,session,rate",
    )
    mod_group.add_argument(
        "--all",
        action="store_true",
        dest="all_modules",
        help="Run all modules",
    )
    mod_group.add_argument("--jwt",        action="store_true", help="JWT attacks module only")
    mod_group.add_argument("--idor",       action="store_true", help="IDOR detection module only")
    mod_group.add_argument("--bypass",     action="store_true", help="Auth bypass module only")
    mod_group.add_argument("--session",    action="store_true", help="Session audit module only")
    mod_group.add_argument("--rate-limit", action="store_true", dest="rate_limit", help="Rate limit module only")

    # ── IDOR options ──────────────────────────────────────────────────────────
    idor_opts = parser.add_argument_group("IDOR options")
    idor_opts.add_argument("--id-param", help="Parameter name for IDOR testing (auto-detect if omitted)")
    idor_opts.add_argument("--id-range", default="1-20", help="ID range to test (default: 1-20)")

    # ── Rate limit options ────────────────────────────────────────────────────
    rate_opts = parser.add_argument_group("Rate limit options")
    rate_opts.add_argument("--wordlist",  help="Username/email wordlist for rate limit testing")
    rate_opts.add_argument(
        "--password",
        default="WrongPass123!",
        help="Password for rate limit testing (default: WrongPass123!)",
    )

    # ── Connection ────────────────────────────────────────────────────────────
    conn_group = parser.add_argument_group("Connection")
    conn_group.add_argument("--proxy",   help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    conn_group.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)",
    )
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
    )
    conn_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Concurrent threads for applicable tests (default: 10)",
    )

    # ── Output ────────────────────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("-o", "--output",     help="JSON report output path")
    out_group.add_argument("--html",             help="HTML report output path")
    out_group.add_argument("--engagement",       help="Engagement ID (embedded in report)")
    out_group.add_argument("-q", "--quiet",      action="store_true", help="Minimal output")

    return parser


# ── Config helpers ────────────────────────────────────────────────────────────

def _parse_headers(header_list: Optional[list[str]]) -> dict:
    """Parse ['Name: Value', ...] to {name: value} dict."""
    headers: dict = {}
    if not header_list:
        return headers
    for raw in header_list:
        if ":" in raw:
            k, _, v = raw.partition(":")
            headers[k.strip()] = v.strip()
        else:
            msg_warn(f"Ignoring malformed header: {raw!r}")
    return headers


def _select_modules(args: argparse.Namespace) -> list[str]:
    """Return ordered list of module keys to run based on CLI flags."""
    if args.all_modules:
        return list(ALL_MODULES.keys())

    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(",")]
        unknown = [m for m in requested if m not in ALL_MODULES]
        if unknown:
            msg_warn(f"Unknown modules ignored: {', '.join(unknown)}")
        return [m for m in requested if m in ALL_MODULES]

    # Individual flags
    selected: list[str] = []
    if args.jwt:
        selected.append("jwt")
    if args.idor:
        selected.append("idor")
    if args.bypass:
        selected.append("bypass")
    if args.session:
        selected.append("session")
    if args.rate_limit:
        selected.append("rate")

    return selected or list(ALL_MODULES.keys())  # default: run all


# ── Summary table ─────────────────────────────────────────────────────────────

def _print_summary(tester: AuthTester, elapsed: float, quiet: bool) -> None:
    """Print final findings summary and stats."""
    stats = tester.get_stats()
    findings = sorted(
        tester.get_findings(),
        key=lambda f: _SEV_ORDER.get(f.severity, 99),
    )

    section("Findings Summary")

    if not findings:
        msg_ok("No vulnerabilities found.")
    else:
        table_header(["Severity", "Module", "Title"])
        for f in findings:
            color = _SEV_COLORS.get(f.severity, "")
            table_row(
                [f.severity.upper().ljust(8), f.module.ljust(10), f.title],
                colors=[color, GRIS, ""],
            )

    section("Statistics")
    sev_counts = stats["findings_by_severity"]
    msg_info(f"Total requests  : {stats['total_requests']}")
    msg_info(f"Elapsed time    : {elapsed:.1f}s")
    msg_info(f"Findings total  : {stats['total_findings']}")

    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count > 0:
            color = _SEV_COLORS.get(sev, "")
            label = sev.upper().ljust(8)
            print(f"  {color}{label}{RESET} : {count}")


# ── JSON / HTML report ────────────────────────────────────────────────────────

def _save_json_report(tester: AuthTester, output_path: str, engagement_id: Optional[str], elapsed: float) -> None:
    """Save findings to a JSON report file."""
    stats = tester.get_stats()
    report = {
        "tool":        "HaakAuth",
        "version":     "1.0.0",
        "engagement":  engagement_id or "",
        "target":      tester.target_url,
        "elapsed":     elapsed,
        "stats":       stats,
        "findings":    [f.to_dict() for f in tester.get_findings()],
    }
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        msg_ok(f"JSON report saved to: {output_path}")
    except OSError as exc:
        msg_warn(f"Could not save JSON report: {exc}")


def _generate_html_report(json_path: str, html_path: str) -> None:
    """Call haakauth_report.py if available to convert JSON to HTML."""
    report_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "haakauth_report.py",
    )
    if not os.path.exists(report_script):
        msg_warn("HTML report generator (haakauth_report.py) not found.")
        return
    try:
        import subprocess
        subprocess.run(
            [sys.executable, report_script, json_path, html_path],
            check=True,
        )
        msg_ok(f"HTML report saved to: {html_path}")
    except Exception as exc:
        msg_warn(f"HTML report generation failed: {exc}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Mostrar banner
    if not args.quiet:
        banner()

    start_time = time.time()

    # ── Validar target ────────────────────────────────────────────────────────
    target_url: Optional[str] = args.url
    headers: dict = _parse_headers(args.header)
    cookies: dict = {}
    token: Optional[str] = args.token

    if args.peticion:
        # Parsear archivo de petición Burp
        msg_info(f"Parsing Burp request file: {args.peticion}")
        try:
            parsed_req = parse_request_file(args.peticion)
        except (FileNotFoundError, ValueError) as exc:
            msg_fail(f"Failed to parse request file: {exc}")
            sys.exit(1)

        target_url = target_url or parsed_req["url"]
        headers.update(parsed_req.get("headers", {}))
        cookies.update(parsed_req.get("cookies", {}))

        # Auto-extraer token del request parseado si no se dio en CLI
        if not token and parsed_req.get("has_auth") and parsed_req.get("auth_type") == "bearer":
            token = parsed_req["auth_value"]
            msg_info(f"Extracted Bearer token from request file (first 40 chars): {token[:40]}...")

    if not target_url:
        msg_fail("No target specified. Use -u <URL> or -p <burp_request.txt>")
        parser.print_help()
        sys.exit(1)

    # Aplicar cookie CLI
    if args.cookie:
        cookies.update(parse_cookies(args.cookie))

    # Aplicar token al header Authorization si se proporcionó
    if token:
        tok_info = parse_token(token)
        if tok_info["type"] in ("bearer", "basic"):
            type_prefix = tok_info["type"].capitalize()
            headers["Authorization"] = f"{type_prefix} {tok_info['value']}"
        elif tok_info["type"] == "custom":
            headers["Authorization"] = tok_info["value"]

    # ── Inicializar AuthTester ────────────────────────────────────────────────
    tester = AuthTester(
        target_url=target_url,
        headers=headers,
        cookies=cookies,
        proxy=args.proxy,
        delay=args.delay,
        timeout=args.timeout,
    )

    msg_info(f"Target  : {target_url}")
    if args.proxy:
        msg_info(f"Proxy   : {args.proxy}")
    msg_info(f"Delay   : {args.delay}s  |  Timeout: {args.timeout}s")

    # ── Opciones de módulos ───────────────────────────────────────────────────
    module_options: dict = {
        "token":    token,
        "token2":   args.token2,
        "cookie2":  args.cookie2,
        "id_param": getattr(args, "id_param", None),
        "id_range": getattr(args, "id_range", "1-20"),
        "wordlist": args.wordlist,
        "password": args.password,
        "threads":  args.threads,
    }

    # ── Seleccionar y ejecutar módulos ────────────────────────────────────────
    selected = _select_modules(args)
    msg_info(f"Modules : {', '.join(selected)}\n")

    for module_key in selected:
        module_cls = ALL_MODULES[module_key]
        module = module_cls(tester=tester, options=module_options)
        section(f"{module.NAME.upper()} — {module.DESCRIPTION}")
        try:
            module.run()
        except KeyboardInterrupt:
            msg_warn(f"\nModule '{module_key}' interrupted by user.")
            break
        except Exception as exc:
            msg_warn(f"Module '{module_key}' raised an unexpected error: {exc}")
            if not args.quiet:
                import traceback
                traceback.print_exc()

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    _print_summary(tester, elapsed, args.quiet)

    # ── Reports ───────────────────────────────────────────────────────────────
    if args.output:
        _save_json_report(tester, args.output, args.engagement, elapsed)

    if args.html:
        if not args.output:
            # Generar JSON temporal para el reporte HTML
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp.close()
            _save_json_report(tester, tmp.name, args.engagement, elapsed)
            _generate_html_report(tmp.name, args.html)
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        else:
            _generate_html_report(args.output, args.html)

    # ── Exit code basado en findings ──────────────────────────────────────────
    findings = tester.get_findings()
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    sys.exit(1 if critical_high else 0)
