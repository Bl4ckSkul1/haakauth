"""
idor_detector.py — IDOR / BOLA detection module for HaakAuth.

Tests implemented:
  1. Auto-detect ID parameters in URL path, query-string and JSON body
  2. Numeric ID manipulation (N±1, N±2, 0, 1, -1, 999999)      (CWE-639)
  3. UUID / GUID manipulation                                    (CWE-639)
  4. Cross-account access (requires --token2 option)            (CWE-639)
  5. Method-based IDOR (PUT/PATCH/DELETE on foreign IDs)        (CWE-639)
  6. Parameter pollution (duplicate param, array notation)       (CWE-235)
  7. Encoding bypass (URL-encoded, Base64, hex IDs)

Only stdlib + requests.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Optional
from urllib.parse import (
    parse_qs, urlencode, urljoin, urlparse, urlunparse, quote,
)

from requests import Response

from auth_tester.core import AuthTester, BaseModule
from auth_tester.colors import (
    msg_fail, msg_info, msg_ok, msg_vuln, msg_warn, progress_bar, section,
)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_ID_PARAM_NAMES: frozenset[str] = frozenset({
    "id", "user_id", "userId", "account_id", "accountId",
    "uid", "pid", "oid", "cid", "tid", "rid",
    "order_id", "orderId", "doc_id", "docId",
    "record_id", "recordId", "customer_id", "customerId",
    "profile_id", "profileId", "emp_id", "empId",
    "ticket_id", "ticketId", "invoice_id", "invoiceId",
    "file_id", "fileId", "patient_id", "patientId",
    "report_id", "reportId", "message_id", "messageId",
})

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_NUMERIC_SEG_RE = re.compile(r"^\d{1,15}$")

# Threshold for "responses differ" content-length comparison
_CONTENT_LEN_THRESHOLD = 50


# ─────────────────────────────────────────────────────────────────────────────
# Response comparison
# ─────────────────────────────────────────────────────────────────────────────

def responses_differ(r1: Response, r2: Response) -> bool:
    """
    Return True if *r2* looks like it returned different data from *r1* —
    an indicator of IDOR (we got someone else's data).

    Logic:
      - Different status codes where r2 succeeds and r1 does not → clear IDOR
      - Both succeed but content length diverges by ≥ threshold → likely IDOR
      - Same status / similar length → attempt JSON key comparison
      - Timestamps, CSRF tokens, and session-specific fields are stripped
        before comparison to reduce false positives.
    """
    ok1 = r1.status_code < 400
    ok2 = r2.status_code < 400

    if ok1 != ok2:
        # One succeeded, the other didn't → different resources / access
        return True

    if not ok1 and not ok2:
        # Both failed — nothing interesting
        return False

    # Both 2xx — compare bodies
    len1 = len(r1.content)
    len2 = len(r2.content)

    if abs(len1 - len2) > _CONTENT_LEN_THRESHOLD:
        return True

    # Try JSON comparison with noise-stripping
    try:
        j1 = _strip_noise(r1.json())
        j2 = _strip_noise(r2.json())
        return j1 != j2
    except Exception:
        # Not JSON or parse error — compare raw text (first 500 chars)
        return r1.text[:500] != r2.text[:500]


_NOISE_KEYS = frozenset({
    "timestamp", "ts", "time", "date", "created_at", "updated_at",
    "csrf", "csrf_token", "_csrf", "csrfToken",
    "nonce", "request_id", "requestId", "trace_id", "traceId",
    "session_id", "sessionId",
})


def _strip_noise(obj: object) -> object:
    """Recursively remove noise keys from a dict/list so comparison is meaningful."""
    if isinstance(obj, dict):
        return {k: _strip_noise(v) for k, v in obj.items() if k not in _NOISE_KEYS}
    if isinstance(obj, list):
        return [_strip_noise(i) for i in obj]
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# ID extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_ids_from_url(url: str) -> list[dict]:
    """
    Extract ID candidates from a URL's path segments and query-string.

    Returns a list of dicts:
        {"kind": "path_segment", "value": "123", "index": 2}
        {"kind": "query_param",  "param": "user_id", "value": "456"}
        {"kind": "uuid_path",    "value": "xxxx-…"}
        {"kind": "uuid_query",   "param": "id", "value": "xxxx-…"}
    """
    parsed = urlparse(url)
    results: list[dict] = []

    # Path segments
    segments = [s for s in parsed.path.split("/") if s]
    for idx, seg in enumerate(segments):
        if _NUMERIC_SEG_RE.match(seg):
            results.append({"kind": "path_segment", "value": seg, "index": idx})
        elif _UUID_RE.fullmatch(seg):
            results.append({"kind": "uuid_path", "value": seg, "index": idx})

    # Query string
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for param, vals in qs.items():
        for val in vals:
            if _NUMERIC_SEG_RE.match(val):
                results.append({"kind": "query_param", "param": param, "value": val})
            elif _UUID_RE.fullmatch(val):
                results.append({"kind": "uuid_query", "param": param, "value": val})
            elif param.lower() in _ID_PARAM_NAMES:
                # Non-numeric but name is suspiciously ID-like
                results.append({"kind": "query_param_named", "param": param, "value": val})

    return results


def _extract_ids_from_body(body: str) -> list[dict]:
    """
    Extract ID fields from a JSON body string.
    Returns: [{"field": "userId", "value": 123}, …]
    """
    results: list[dict] = []
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower().replace("_", "") in {n.lower().replace("_", "") for n in _ID_PARAM_NAMES}:
                    results.append({"field": k, "value": v})
                elif isinstance(v, int) and k.lower().endswith("id"):
                    results.append({"field": k, "value": v})
    except (json.JSONDecodeError, TypeError):
        pass
    return results


def _replace_path_id(url: str, old_val: str, new_val: str) -> str:
    """Replace the first occurrence of *old_val* as a path segment."""
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    for i, seg in enumerate(parts):
        if seg == old_val:
            parts[i] = new_val
            break
    new_path = "/".join(parts)
    return urlunparse(parsed._replace(path=new_path))


def _replace_query_param(url: str, param: str, new_val: str) -> str:
    """Replace the value of *param* in the query string."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_val]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


# ─────────────────────────────────────────────────────────────────────────────
# IDORModule
# ─────────────────────────────────────────────────────────────────────────────

class IDORModule(BaseModule):
    """IDOR / BOLA detection via ID manipulation, cross-account testing and more."""

    NAME        = "idor_detector"
    DESCRIPTION = (
        "Detects IDOR/BOLA vulnerabilities through numeric ID manipulation, "
        "UUID substitution, cross-account access, method-based IDOR, "
        "parameter pollution, and encoding bypasses."
    )
    _TOTAL_TESTS = 7

    def __init__(self, tester: AuthTester, options: Optional[dict] = None):
        super().__init__(tester, options)
        self._url_ids: list[dict] = []
        self._original_resp: Optional[Response] = None
        self._done = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _tick(self, label: str) -> None:
        self._done += 1
        progress_bar(self._done, self._TOTAL_TESTS, label)

    def _get(self, url: str, headers: Optional[dict] = None,
             cookies: Optional[dict] = None) -> Optional[Response]:
        try:
            return self.tester.get(
                url,
                headers=headers or {},
                cookies=cookies or {},
                allow_redirects=False,
            )
        except Exception as exc:
            msg_warn(f"  Request error: {exc}")
            return None

    def _request_with_method(self, method: str, url: str, **kwargs) -> Optional[Response]:
        try:
            return self.tester.request(method, url, allow_redirects=False, **kwargs)
        except Exception as exc:
            msg_warn(f"  {method} request error: {exc}")
            return None

    def _build_token2_headers(self) -> Optional[dict]:
        """Build Authorization header for the second account token."""
        token2: Optional[str] = self.options.get("token2")
        if not token2:
            return None
        tok = token2.strip()
        prefix = "Bearer " if not tok.lower().startswith("bearer ") else ""
        return {"Authorization": f"{prefix}{tok}"}

    def _build_token2_cookies(self) -> dict:
        cookie2: Optional[str] = self.options.get("cookie2")
        if not cookie2:
            return {}
        cookies = {}
        for part in cookie2.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    # ─────────────────────────────────────────────────────────────────────────
    # Test 1 — Auto-detect ID parameters
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_ids(self) -> None:
        msg_info("Test 1/7: Auto-detecting ID parameters")
        url = self.tester.target_url

        self._url_ids = _extract_ids_from_url(url)

        # Also try the request body if provided via option
        body: str = self.options.get("body", "")
        body_ids = _extract_ids_from_body(body) if body else []

        if self._url_ids:
            msg_ok(f"Found {len(self._url_ids)} ID candidate(s) in URL:")
            for item in self._url_ids:
                msg_info(f"    {item}")
        else:
            msg_info("  No IDs detected in URL path or query string")

        if body_ids:
            msg_ok(f"Found {len(body_ids)} ID candidate(s) in request body:")
            for item in body_ids:
                msg_info(f"    {item}")

        # Store baseline authenticated response
        self._original_resp = self._get(url)
        if self._original_resp:
            msg_info(f"  Baseline: {self._original_resp.status_code}")
        else:
            msg_warn("  Baseline request failed")

        self._tick("id detection")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 2 — Numeric ID manipulation
    # ─────────────────────────────────────────────────────────────────────────

    def _test_numeric_ids(self) -> None:
        msg_info("Test 2/7: Numeric ID Manipulation")
        numeric_ids = [x for x in self._url_ids
                       if x["kind"] in ("path_segment", "query_param")]

        if not numeric_ids:
            msg_info("  No numeric IDs found in URL — skipping")
            self._tick("numeric ID"); return

        for id_info in numeric_ids[:3]:  # Test at most 3 distinct IDs to keep noise low
            original_val = id_info["value"]
            n = int(original_val)
            probes = [n - 1, n + 1, n - 2, n + 2, 1, 0, -1, 999999]
            probes = [p for p in probes if str(p) != original_val]

            found_any = False
            for i, probe in enumerate(probes):
                progress_bar(i + 1, len(probes), f"id={probe}")
                probe_str = str(probe)

                if id_info["kind"] == "path_segment":
                    test_url = _replace_path_id(
                        self.tester.target_url, original_val, probe_str)
                else:
                    test_url = _replace_query_param(
                        self.tester.target_url, id_info["param"], probe_str)

                resp = self._get(test_url)
                if resp is None:
                    continue

                if self._original_resp and responses_differ(self._original_resp, resp):
                    if resp.status_code < 400:
                        msg_vuln("high", f"IDOR: id={probe} returns different data → {resp.status_code}")
                        self.finding(
                            severity="high",
                            title=f"IDOR — Numeric ID Manipulation (id={probe})",
                            description=(
                                f"Replacing the original ID ({original_val}) with {probe} "
                                "returned a different successful response, indicating access to "
                                "a different user's data without authorization."
                            ),
                            evidence=(
                                f"Original id={original_val} → {self._original_resp.status_code}\n"
                                f"Probe    id={probe}       → {resp.status_code}\n"
                                f"URL: {test_url}\nBody: {resp.text[:200]}"
                            ),
                            cwe="CWE-639",
                            remediation=(
                                "Implement server-side ownership validation. "
                                "Never trust IDs supplied by the client — "
                                "derive the owner from the authenticated session."
                            ),
                            request_data=self._request_data("GET", test_url, {}),
                            response_data=self._response_data(resp),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                                "https://cwe.mitre.org/data/definitions/639.html",
                            ],
                        )
                        found_any = True; break
                    else:
                        msg_fail(f"  id={probe} → {resp.status_code}")
                else:
                    msg_fail(f"  id={probe} → {resp.status_code} (same data or error)")

            if not found_any:
                msg_ok(f"  Numeric IDOR not detected for id={original_val}")

        self._tick("numeric ID")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 3 — UUID / GUID manipulation
    # ─────────────────────────────────────────────────────────────────────────

    def _test_uuid_ids(self) -> None:
        msg_info("Test 3/7: UUID / GUID Manipulation")
        uuid_ids = [x for x in self._url_ids if x["kind"] in ("uuid_path", "uuid_query")]

        if not uuid_ids:
            msg_info("  No UUID IDs found in URL — skipping")
            self._tick("UUID IDs"); return

        for id_info in uuid_ids[:2]:
            original_val = id_info["value"]
            null_uuid    = "00000000-0000-0000-0000-000000000000"
            # Sequential: change last 4 hex chars
            seq_uuid = original_val[:-4] + (
                format(int(original_val[-4:], 16) + 1, "04x")
                if all(c in "0123456789abcdefABCDEF" for c in original_val[-4:])
                else "ffff"
            )

            probes = [
                ("null_uuid",       null_uuid),
                ("sequential_uuid", seq_uuid),
            ]

            for label, probe_val in probes:
                if id_info["kind"] == "uuid_path":
                    test_url = _replace_path_id(
                        self.tester.target_url, original_val, probe_val)
                else:
                    test_url = _replace_query_param(
                        self.tester.target_url, id_info["param"], probe_val)

                resp = self._get(test_url)
                if resp is None:
                    continue

                if resp.status_code < 400 and self._original_resp and responses_differ(
                        self._original_resp, resp):
                    msg_vuln("high", f"UUID IDOR: {label} returned different data → {resp.status_code}")
                    self.finding(
                        severity="high",
                        title=f"IDOR — UUID ID Manipulation ({label})",
                        description=(
                            f"Replacing UUID {original_val!r} with {probe_val!r} ({label}) "
                            "returned a different successful response. "
                            "UUID predictability or lack of ownership checks may allow IDOR."
                        ),
                        evidence=(
                            f"Original: {original_val} → {self._original_resp.status_code}\n"
                            f"Probe ({label}): {probe_val} → {resp.status_code}\n"
                            f"Body: {resp.text[:200]}"
                        ),
                        cwe="CWE-639",
                        remediation=(
                            "Use non-guessable UUIDs (v4) and enforce ownership "
                            "checks server-side regardless of the ID format."
                        ),
                        request_data=self._request_data("GET", test_url, {}),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/639.html"],
                    )
                elif resp.status_code < 400:
                    msg_info(f"  {label} succeeded but content looks the same → {resp.status_code}")
                else:
                    msg_fail(f"  {label} → {resp.status_code}")

        msg_ok("UUID manipulation tests complete")
        self._tick("UUID IDs")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 4 — Cross-account access
    # ─────────────────────────────────────────────────────────────────────────

    def _test_cross_account(self) -> None:
        msg_info("Test 4/7: Cross-Account Access (BOLA)")
        hdrs2  = self._build_token2_headers()
        cook2  = self._build_token2_cookies()

        if not hdrs2 and not cook2:
            msg_info("  No --token2 / --cookie2 provided — skipping cross-account test")
            self._tick("cross-account"); return

        # Step A: get account-1 resource IDs from the original response
        if not self._original_resp:
            msg_warn("  No baseline response available — skipping")
            self._tick("cross-account"); return

        # Attempt to extract IDs from original response body
        resource_ids: list[str] = []
        try:
            body_obj = self._original_resp.json()
            raw_text = json.dumps(body_obj)
            resource_ids = _UUID_RE.findall(raw_text)
            # Also grab numerics from id fields
            if isinstance(body_obj, dict):
                for fld in ("id", "user_id", "userId", "accountId"):
                    if fld in body_obj and str(body_obj[fld]).isdigit():
                        resource_ids.append(str(body_obj[fld]))
        except Exception:
            resource_ids = []

        # Step B: try accessing target URL with account-2 credentials
        resp2 = self._get(self.tester.target_url, headers=hdrs2, cookies=cook2)
        if resp2 is None:
            msg_warn("  Cross-account request failed")
            self._tick("cross-account"); return

        if resp2.status_code < 400:
            if self._original_resp and responses_differ(self._original_resp, resp2):
                msg_vuln("critical", f"Cross-account IDOR: account B accessed account A's resource → {resp2.status_code}")
                self.finding(
                    severity="critical",
                    title="IDOR — Cross-Account Access (BOLA)",
                    description=(
                        "Account B was able to access the resource URL belonging to Account A "
                        "and received different content, confirming BOLA (Broken Object Level "
                        "Authorization). This is the gold standard IDOR confirmation."
                    ),
                    evidence=(
                        f"Account A response: {self._original_resp.status_code}\n"
                        f"Account B response: {resp2.status_code}\n"
                        f"URL: {self.tester.target_url}\n"
                        f"Account B body: {resp2.text[:300]}"
                    ),
                    cwe="CWE-639",
                    remediation=(
                        "Validate that the authenticated user owns every object they request. "
                        "The owner ID must come from the server-side session, not URL parameters."
                    ),
                    request_data=self._request_data("GET", self.tester.target_url,
                                                    hdrs2 or {}),
                    response_data=self._response_data(resp2),
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/639.html",
                    ],
                )
            else:
                msg_info(f"  Account B accessed same URL but got same data → may be own data or public ({resp2.status_code})")
        else:
            msg_ok(f"  Account B correctly received {resp2.status_code}")

        self._tick("cross-account")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 5 — Method-based IDOR
    # ─────────────────────────────────────────────────────────────────────────

    def _test_method_idor(self) -> None:
        msg_info("Test 5/7: Method-Based IDOR (PUT/PATCH/DELETE on foreign IDs)")
        numeric_ids = [x for x in self._url_ids
                       if x["kind"] in ("path_segment", "query_param")]

        if not numeric_ids:
            msg_info("  No numeric IDs found — skipping method-based IDOR")
            self._tick("method IDOR"); return

        id_info = numeric_ids[0]
        original_val = id_info["value"]
        n = int(original_val)

        # Pick a different ID for the write attempt
        foreign_id = str(n + 1)

        if id_info["kind"] == "path_segment":
            foreign_url = _replace_path_id(self.tester.target_url, original_val, foreign_id)
        else:
            foreign_url = _replace_query_param(
                self.tester.target_url, id_info["param"], foreign_id)

        write_methods = ["PUT", "PATCH", "DELETE"]
        probe_body = json.dumps({"test": "haakauth-idor-probe"})

        for method in write_methods:
            resp = self._request_with_method(
                method, foreign_url,
                data=probe_body,
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            if resp.status_code < 400:
                severity = "critical" if method == "DELETE" else "high"
                msg_vuln(severity, f"Method IDOR: {method} on foreign id={foreign_id} accepted → {resp.status_code}")
                self.finding(
                    severity=severity,
                    title=f"IDOR — {method} Access on Foreign Resource (id={foreign_id})",
                    description=(
                        f"The {method} method on a resource owned by a different user "
                        f"(id={foreign_id}) returned HTTP {resp.status_code}. "
                        f"This allows {'deletion' if method == 'DELETE' else 'modification'} "
                        "of other users' data."
                    ),
                    evidence=(
                        f"Method: {method}\nURL: {foreign_url}\n"
                        f"Status: {resp.status_code}\nBody: {resp.text[:200]}"
                    ),
                    cwe="CWE-639",
                    remediation=(
                        "Enforce ownership checks on all mutating HTTP methods, not only GET. "
                        "Authorization controls must be method-agnostic."
                    ),
                    request_data=self._request_data(method, foreign_url, {}, probe_body),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/639.html"],
                )
            else:
                msg_fail(f"  {method} on id={foreign_id} → {resp.status_code}")

        self._tick("method IDOR")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 6 — Parameter pollution
    # ─────────────────────────────────────────────────────────────────────────

    def _test_param_pollution(self) -> None:
        msg_info("Test 6/7: Parameter Pollution")
        numeric_ids = [x for x in self._url_ids if x["kind"] == "query_param"]

        if not numeric_ids:
            # Try to find a query-param we can pollute; if none, add a synthetic one
            parsed = urlparse(self.tester.target_url)
            if not parsed.query:
                msg_info("  No query-string IDs found — skipping parameter pollution")
                self._tick("param pollution"); return
            numeric_ids = [{"kind": "query_param", "param": "id",
                             "value": "1"}]  # synthetic

        id_info = numeric_ids[0]
        param   = id_info["param"]
        orig    = id_info["value"]
        foreign = str(int(orig) + 1) if orig.isdigit() else "2"

        parsed = urlparse(self.tester.target_url)
        base_url = urlunparse(parsed._replace(query=""))
        qs = parse_qs(parsed.query, keep_blank_values=True)

        def _build(extra_qs: dict) -> str:
            merged = {**{k: v[0] for k, v in qs.items()}, **extra_qs}
            return f"{base_url}?{urlencode(merged)}"

        variants: list[tuple[str, str]] = [
            ("duplicate_param",    f"{base_url}?{param}={orig}&{param}={foreign}"),
            ("array_notation",     _build({f"{param}[]": foreign})),
            ("csv_values",         _build({param: f"{orig},{foreign}"})),
        ]

        # JSON body pollution (POST)
        json_variants: list[tuple[str, dict]] = [
            ("json_array",  {"id": [int(orig), int(foreign)]}),
            ("nested_id",   {"user": {"id": int(foreign)}}),
        ]

        found = False
        for label, test_url in variants:
            resp = self._get(test_url)
            if resp is None:
                continue
            if resp.status_code < 400 and self._original_resp and responses_differ(
                    self._original_resp, resp):
                msg_vuln("medium", f"Param pollution: {label} → {resp.status_code} (different data)")
                self.finding(
                    severity="medium",
                    title=f"IDOR via Parameter Pollution ({label})",
                    description=(
                        f"Sending duplicate/array parameter '{param}' returned different data, "
                        "which may indicate access to another user's resource."
                    ),
                    evidence=f"URL: {test_url}\nStatus: {resp.status_code}\nBody: {resp.text[:200]}",
                    cwe="CWE-235",
                    remediation=(
                        "Use only the first occurrence of each parameter. "
                        "Reject requests containing duplicate or array-notation ID parameters."
                    ),
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/235.html"],
                )
                found = True
            else:
                msg_fail(f"  {label} → {resp.status_code if resp else 'error'}")

        for label, body_obj in json_variants:
            resp = self._request_with_method(
                "POST", self.tester.target_url,
                json=body_obj,
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.status_code < 400 and self._original_resp and responses_differ(
                    self._original_resp, resp):
                msg_vuln("medium", f"JSON pollution: {label} → {resp.status_code}")
                self.finding(
                    severity="medium",
                    title=f"IDOR via JSON Body Pollution ({label})",
                    description=(
                        "Sending an array or nested ID in the JSON body returned different "
                        "data, suggesting the server processed a foreign resource ID."
                    ),
                    evidence=f"Body: {json.dumps(body_obj)}\nStatus: {resp.status_code}",
                    cwe="CWE-235",
                    remediation="Validate that array/nested IDs in request bodies belong to the authenticated user.",
                    request_data=self._request_data("POST", self.tester.target_url, {},
                                                    json.dumps(body_obj)),
                    response_data=self._response_data(resp),
                )
                found = True
            else:
                msg_fail(f"  JSON {label} → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Parameter pollution: no IDOR indicators found")
        self._tick("param pollution")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 7 — Encoding bypass
    # ─────────────────────────────────────────────────────────────────────────

    def _test_encoding_bypass(self) -> None:
        msg_info("Test 7/7: Encoding Bypass (URL-encoded, Base64, Hex IDs)")
        numeric_ids = [x for x in self._url_ids
                       if x["kind"] in ("path_segment", "query_param")]

        if not numeric_ids:
            msg_info("  No numeric IDs — skipping encoding bypass")
            self._tick("encoding bypass"); return

        id_info     = numeric_ids[0]
        original    = id_info["value"]
        foreign     = str(int(original) + 1) if original.isdigit() else "2"

        # Build encoding variants for the foreign ID
        hex_id      = hex(int(foreign))
        url_encoded = quote(foreign, safe="")          # %31%32%33 …
        double_enc  = quote(url_encoded, safe="")
        b64_id      = base64.b64encode(foreign.encode()).decode()

        probe_map: dict[str, str] = {
            "url_encoded":    url_encoded,
            "double_encoded": double_enc,
            "hex":            hex_id,
            "base64":         b64_id,
        }

        # Also check if *existing* param value looks base64 (decode → different ID)
        try:
            decoded = base64.b64decode(original + "==").decode("utf-8", errors="ignore")
            if decoded.isdigit():
                probe_map["b64_decoded_increment"] = base64.b64encode(
                    str(int(decoded) + 1).encode()).decode()
        except Exception:
            pass

        found = False
        for label, probe_val in probe_map.items():
            if id_info["kind"] == "path_segment":
                test_url = _replace_path_id(self.tester.target_url, original, probe_val)
            else:
                test_url = _replace_query_param(
                    self.tester.target_url, id_info["param"], probe_val)

            resp = self._get(test_url)
            if resp is None:
                continue

            if resp.status_code < 400 and self._original_resp and responses_differ(
                    self._original_resp, resp):
                msg_vuln("medium", f"Encoding bypass: {label} ({probe_val!r}) returned different data → {resp.status_code}")
                self.finding(
                    severity="medium",
                    title=f"IDOR via Encoding Bypass ({label})",
                    description=(
                        f"Using {label} encoding of ID={foreign} ({probe_val!r}) "
                        "returned different data, indicating the server decoded the value "
                        "and performed a different object lookup without ownership validation."
                    ),
                    evidence=(
                        f"Encoding: {label}\nValue: {probe_val}\n"
                        f"URL: {test_url}\nStatus: {resp.status_code}\nBody: {resp.text[:200]}"
                    ),
                    cwe="CWE-639",
                    remediation=(
                        "Decode and normalize IDs before performing ownership checks. "
                        "Apply authorization after full URL / parameter decoding."
                    ),
                    request_data=self._request_data("GET", test_url, {}),
                    response_data=self._response_data(resp),
                    references=["https://cwe.mitre.org/data/definitions/639.html"],
                )
                found = True
            else:
                msg_fail(f"  {label} ({probe_val!r}) → {resp.status_code if resp else 'error'}")

        if not found:
            msg_ok("Encoding bypass: no IDOR indicators found")
        self._tick("encoding bypass")

    # ─────────────────────────────────────────────────────────────────────────
    # run()
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        section(f"Module: {self.NAME}")
        msg_info(f"Target : {self.tester.target_url}")

        self._detect_ids()
        self._test_numeric_ids()
        self._test_uuid_ids()
        self._test_cross_account()
        self._test_method_idor()
        self._test_param_pollution()
        self._test_encoding_bypass()

        msg_info(
            f"IDOR module complete — {self.tester.request_count} total requests, "
            f"{len(self.tester.get_findings())} total findings so far"
        )
