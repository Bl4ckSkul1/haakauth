"""
core.py — HTTP engine, session management, Finding model y BaseModule.
Todos los módulos usan AuthTester como backend de requests y Finding como
estructura de reporte.
"""
from __future__ import annotations

import time
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response

from .colors import msg_info, msg_warn


# ── Utilidades de URL / headers ───────────────────────────────────────────────

def extract_base_url(url: str) -> str:
    """Devuelve solo scheme + host + puerto de una URL."""
    parsed = urlparse(url)
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{parsed.netloc.split(':')[0]}{port}"


def parse_token(auth_header: str) -> dict:
    """Extrae tipo y valor de un header Authorization.

    Returns:
        {"type": "bearer" | "basic" | "custom", "value": "..."}
    """
    stripped = auth_header.strip()
    lower = stripped.lower()
    if lower.startswith("bearer "):
        return {"type": "bearer", "value": stripped[7:].strip()}
    if lower.startswith("basic "):
        return {"type": "basic", "value": stripped[6:].strip()}
    # Token sin prefijo conocido → custom
    return {"type": "custom", "value": stripped}


def parse_cookies(cookie_str: str) -> dict:
    """Parsea una cadena 'name=val; name2=val2' a dict."""
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Representación de un hallazgo de seguridad."""

    severity: str               # critical | high | medium | low | info
    title: str
    description: str
    evidence: str               # fragmento de respuesta, header, etc.
    module: str                 # jwt | idor | bypass | session | rate_limit
    request_data: dict = field(default_factory=dict)   # method, url, headers, body
    response_data: dict = field(default_factory=dict)  # status_code, headers, body
    remediation: str = ""
    cwe: str = ""               # CWE-XXX
    references: list = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "evidence":      self.evidence,
            "module":        self.module,
            "request_data":  self.request_data,
            "response_data": self.response_data,
            "remediation":   self.remediation,
            "cwe":           self.cwe,
            "references":    self.references,
            "timestamp":     self.timestamp,
        }


# ── AuthTester ────────────────────────────────────────────────────────────────

class AuthTester:
    """Motor HTTP central para pruebas de autenticación y autorización."""

    def __init__(
        self,
        target_url: str,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        proxy: Optional[str] = None,
        delay: float = 0.5,
        timeout: int = 15,
        verify_ssl: bool = False,
    ):
        self.target_url = target_url
        self.base_url = extract_base_url(target_url)
        self.delay = delay
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.results: list[Finding] = []
        self.request_count: int = 0
        self._start_time: float = time.time()

        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        self.session.verify = verify_ssl

        # Suprimir warnings de SSL si verify=False
        if not verify_ssl:
            try:
                import urllib3  # type: ignore[import]
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    # ── HTTP primitives ───────────────────────────────────────────────────────

    def request(self, method: str, url: str, **kwargs) -> Response:
        """Realiza una petición HTTP con delay, proxy y conteo."""
        if self.delay > 0:
            time.sleep(self.delay)

        kwargs.setdefault("timeout", self.timeout)
        if self.proxy:
            kwargs.setdefault("proxies", self.proxy)

        try:
            resp = self.session.request(method.upper(), url, **kwargs)
            self.request_count += 1
            return resp
        except requests.exceptions.SSLError as exc:
            msg_warn(f"SSL error en {url}: {exc}")
            raise
        except requests.exceptions.ConnectionError as exc:
            msg_warn(f"Connection error en {url}: {exc}")
            raise
        except requests.exceptions.Timeout:
            msg_warn(f"Timeout ({self.timeout}s) en {url}")
            raise

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs) -> Response:
        return self.request("PATCH", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        request_data: Optional[dict] = None,
        response_data: Optional[dict] = None,
        module: str = "unknown",
        remediation: str = "",
        cwe: str = "",
        references: Optional[list] = None,
    ) -> Finding:
        """Crea y almacena un Finding."""
        f = Finding(
            severity=severity.lower(),
            title=title,
            description=description,
            evidence=evidence,
            module=module,
            request_data=request_data or {},
            response_data=response_data or {},
            remediation=remediation,
            cwe=cwe,
            references=references or [],
        )
        self.results.append(f)
        return f

    def get_findings(self) -> list[Finding]:
        return list(self.results)

    def get_stats(self) -> dict:
        """Estadísticas de la sesión."""
        elapsed = time.time() - self._start_time
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.results:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "total_requests": self.request_count,
            "total_findings": len(self.results),
            "elapsed_seconds": round(elapsed, 2),
            "findings_by_severity": counts,
        }


# ── BaseModule ────────────────────────────────────────────────────────────────

class BaseModule:
    """Clase base para todos los módulos de HaakAuth."""

    NAME: str = "base"
    DESCRIPTION: str = "Base module"

    def __init__(self, tester: AuthTester, options: Optional[dict] = None):
        self.tester = tester
        self.options = options or {}

    def run(self) -> None:
        """Ejecuta todas las pruebas del módulo. Debe ser implementado por subclases."""
        raise NotImplementedError(f"El módulo '{self.NAME}' no implementa run()")

    def finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        **kwargs,
    ) -> Finding:
        """Shortcut para agregar un hallazgo con el módulo actual."""
        return self.tester.add_finding(
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            module=self.NAME,
            **kwargs,
        )

    @staticmethod
    def _safe_body(resp: Response, max_len: int = 500) -> str:
        """Extrae el cuerpo de una respuesta truncado a max_len chars."""
        try:
            return resp.text[:max_len]
        except Exception:
            return "<undecodable body>"

    @staticmethod
    def _response_data(resp: Response, max_body: int = 500) -> dict:
        """Construye el dict response_data estándar de un Finding."""
        return {
            "status_code": resp.status_code,
            "headers":     dict(resp.headers),
            "body":        BaseModule._safe_body(resp, max_body),
        }

    @staticmethod
    def _request_data(method: str, url: str, headers: dict, body: str = "") -> dict:
        """Construye el dict request_data estándar de un Finding."""
        return {
            "method":  method.upper(),
            "url":     url,
            "headers": headers,
            "body":    body,
        }
