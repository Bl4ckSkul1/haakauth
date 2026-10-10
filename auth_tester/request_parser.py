"""
request_parser.py — Parsea archivos de petición raw de Burp Suite.
Soporta HTTP/1.1 y HTTP/2. Auto-detecta mecanismo de autenticación.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus


# ── Detección de autenticación ────────────────────────────────────────────────

_API_KEY_HEADERS = {
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-token", "x-secret", "access-token", "auth-token",
}

_COOKIE_SESSION_NAMES = {
    "session", "sessid", "sid", "token", "auth", "jwt",
    "access_token", "refresh_token", "phpsessid", "jsessionid",
    "asp.net_sessionid",
}


def _detect_auth(
    headers: dict[str, str],
    cookies: dict[str, str],
) -> tuple[bool, str, str]:
    """Detecta el mecanismo de autenticación presente.

    Returns:
        (has_auth, auth_type, auth_value)
        auth_type: bearer | basic | cookie | api_key | custom
    """
    # 1. Authorization header
    auth_hdr = headers.get("authorization", "")
    if auth_hdr:
        lower = auth_hdr.lower()
        if lower.startswith("bearer "):
            return True, "bearer", auth_hdr[7:].strip()
        if lower.startswith("basic "):
            return True, "basic", auth_hdr[6:].strip()
        return True, "custom", auth_hdr.strip()

    # 2. API key headers conocidos
    for hname, hval in headers.items():
        if hname.lower() in _API_KEY_HEADERS:
            return True, "api_key", hval

    # 3. Cookies de sesión
    for cname, cval in cookies.items():
        if cname.lower() in _COOKIE_SESSION_NAMES:
            return True, "cookie", cval

    # 4. Sin auth detectada
    return False, "none", ""


def _extract_params(body: str, content_type: str) -> list[str]:
    """Extrae nombres de parámetros del body (JSON o form-encoded)."""
    ct = content_type.lower()
    params: list[str] = []

    if "application/json" in ct:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                params = list(data.keys())
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in ct:
        try:
            parsed = parse_qs(body, keep_blank_values=True)
            params = list(parsed.keys())
        except Exception:
            pass
    elif "multipart/form-data" in ct:
        # Detecta nombres de campos multipart
        params = re.findall(r'Content-Disposition:[^\n]*name="([^"]+)"', body)

    return params


# ── Parser principal ──────────────────────────────────────────────────────────

def parse_request_file(filepath: str) -> dict:
    """Parsea un archivo de petición raw de Burp Suite.

    Soporta:
    - HTTP/1.1 y HTTP/2 (línea de request con o sin versión)
    - Body JSON y form-encoded
    - Auto-detección de host y reconstrucción de URL completa
    - Detección automática de mecanismo de autenticación

    Returns:
        {
            "method":        str,
            "url":           str,
            "headers":       dict[str, str],
            "body":          str,
            "cookies":       dict[str, str],
            "content_type":  str,
            "has_auth":      bool,
            "auth_type":     str,   # bearer | basic | cookie | api_key | custom | none
            "auth_value":    str,
            "target_params": list[str],
        }
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Request file not found: {filepath}")

    # Leer raw — intentar UTF-8, fallback latin-1
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = path.read_text(encoding="latin-1")

    lines = raw.splitlines()
    if not lines:
        raise ValueError("Empty request file.")

    # ── Línea de request (METHOD /path HTTP/X.X o METHOD /path) ──────────────
    first_line = lines[0].strip()
    rl_match = re.match(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)(?:\s+HTTP/[\d.]+)?",
        first_line,
        re.IGNORECASE,
    )
    if not rl_match:
        raise ValueError(f"Cannot parse request line: {first_line!r}")

    method = rl_match.group(1).upper()
    raw_path = rl_match.group(2)

    # ── Headers ───────────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    host = ""

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key_stripped = key.strip()
                val_stripped = val.strip()
                headers[key_stripped] = val_stripped
                if key_stripped.lower() == "host":
                    host = val_stripped
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()

    # ── Reconstruir URL completa ───────────────────────────────────────────────
    if raw_path.lower().startswith("http://") or raw_path.lower().startswith("https://"):
        # URL absoluta (HTTP/2 o proxy directo)
        url = raw_path
    else:
        # Relativa — inferir esquema del puerto del host o cabecera X-Forwarded-Proto
        scheme = "https"
        forwarded_proto = headers.get("x-forwarded-proto", "").lower()
        if forwarded_proto in ("http", "https"):
            scheme = forwarded_proto
        elif host.endswith(":80"):
            scheme = "http"
        # Normalizar host (quitar puerto default)
        clean_host = host.rstrip("/")
        url = f"{scheme}://{clean_host}{raw_path}"

    # ── Cookies ───────────────────────────────────────────────────────────────
    cookies: dict[str, str] = {}
    cookie_hdr = headers.get("Cookie", headers.get("cookie", ""))
    if cookie_hdr:
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = unquote_plus(v.strip())

    # ── Content-Type ──────────────────────────────────────────────────────────
    content_type = headers.get(
        "Content-Type", headers.get("content-type", "")
    ).lower()

    # ── Auth detection ────────────────────────────────────────────────────────
    # Normalizar headers a lowercase para búsqueda
    headers_lower = {k.lower(): v for k, v in headers.items()}
    has_auth, auth_type, auth_value = _detect_auth(headers_lower, cookies)

    # ── Parámetros de inyección ────────────────────────────────────────────────
    target_params = _extract_params(body, content_type)

    # ── Mantener headers con sus keys originales ──────────────────────────────
    return {
        "method":        method,
        "url":           url,
        "headers":       headers,
        "body":          body,
        "cookies":       cookies,
        "content_type":  content_type,
        "has_auth":      has_auth,
        "auth_type":     auth_type,
        "auth_value":    auth_value,
        "target_params": target_params,
    }
