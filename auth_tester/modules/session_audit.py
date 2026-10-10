"""
session_audit.py — Session management security audit module.

Tests:
  1. Cookie security flags (HttpOnly, Secure, SameSite, etc.)
  2. Session token entropy
  3. Session fixation
  4. Concurrent session handling
  5. Logout / token invalidation
  6. Security headers audit
  7. CORS configuration
  8. Token in URL / Referer leakage
"""
from __future__ import annotations

import re
import string
import math
import time
from urllib.parse import urlparse, urlencode, urljoin, parse_qs

import requests
from requests.exceptions import RequestException, ConnectionError as ReqConnError, Timeout

from auth_tester.core import BaseModule, AuthTester
from auth_tester.colors import (
    msg_info, msg_ok, msg_fail, msg_vuln, msg_warn, section, progress_bar,
)
from auth_tester.data.payloads import LOGOUT_ENDPOINTS, SECURITY_HEADERS, CORS_TEST_ORIGINS


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_set_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie header value into a structured dict."""
    parts = [p.strip() for p in raw.split(";")]
    result: dict = {}
    if parts:
        name_val = parts[0]
        if "=" in name_val:
            k, _, v = name_val.partition("=")
            result["name"] = k.strip()
            result["value"] = v.strip()
        else:
            result["name"] = name_val
            result["value"] = ""
    for part in parts[1:]:
        low = part.lower()
        if low == "httponly":
            result["httponly"] = True
        elif low == "secure":
            result["secure"] = True
        elif low.startswith("samesite="):
            result["samesite"] = part.split("=", 1)[1].strip().lower()
        elif low.startswith("path="):
            result["path"] = part.split("=", 1)[1].strip()
        elif low.startswith("domain="):
            result["domain"] = part.split("=", 1)[1].strip()
        elif low.startswith("expires="):
            result["expires"] = part.split("=", 1)[1].strip()
        elif low.startswith("max-age="):
            result["max_age"] = part.split("=", 1)[1].strip()
    return result


def _token_entropy(tokens: list[str]) -> float:
    """Shannon entropy estimate for a list of tokens (bits per char * avg_len)."""
    if not tokens:
        return 0.0
    combined = "".join(tokens)
    if not combined:
        return 0.0
    freq: dict[str, int] = {}
    for ch in combined:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(combined)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    avg_len = total / len(tokens)
    return entropy * avg_len


def _looks_sequential(tokens: list[str]) -> bool:
    """Return True if tokens look like base64-encoded incrementing integers."""
    import base64
    decoded_ints = []
    for tok in tokens:
        try:
            padded = tok + "=" * (-len(tok) % 4)
            raw = base64.b64decode(padded)
            decoded_ints.append(int.from_bytes(raw, "big"))
        except Exception:
            return False
    if len(decoded_ints) < 2:
        return False
    diffs = [decoded_ints[i + 1] - decoded_ints[i] for i in range(len(decoded_ints) - 1)]
    # Sequential if all diffs are the same small positive integer
    return len(set(diffs)) == 1 and 0 < diffs[0] <= 10


def _is_session_cookie(name: str) -> bool:
    """Heuristic: is this cookie likely a session identifier?"""
    keywords = [
        "sess", "session", "sid", "auth", "token", "jwt", "access",
        "refresh", "id", "user", "login", "credential", "bearer",
    ]
    low = name.lower()
    return any(kw in low for kw in keywords)


# ── module ────────────────────────────────────────────────────────────────────

class SessionModule(BaseModule):
    NAME = "session"
    DESCRIPTION = "Session management security audit (cookies, entropy, fixation, CORS, headers)"

    # ── run ───────────────────────────────────────────────────────────────────

    def run(self) -> None:
        section("Session Management Audit")

        self._test_cookie_flags()
        self._test_token_entropy()
        self._test_session_fixation()
        self._test_concurrent_sessions()
        self._test_logout_invalidation()
        self._test_security_headers()
        self._test_cors()
        self._test_token_in_url()

    # ── Test 1: Cookie security flags ─────────────────────────────────────────

    def _test_cookie_flags(self) -> None:
        msg_info("Test 1/8 — Cookie security flags")
        try:
            resp = self.tester.get(self.tester.target_url)
        except RequestException as exc:
            msg_warn(f"  Cookie flags: request failed — {exc}")
            return

        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        # Fallback: collect from response.headers (only last Set-Cookie visible)
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                raw_cookies = [sc]

        if not raw_cookies:
            msg_info("  No Set-Cookie headers in response — skipping flag checks")
            return

        is_https = self.tester.target_url.startswith("https://")
        findings_made = 0

        for raw in raw_cookies:
            cookie = _parse_set_cookie(raw)
            name = cookie.get("name", "<unknown>")
            is_session = _is_session_cookie(name)

            # HttpOnly
            if not cookie.get("httponly") and is_session:
                msg_vuln("high", f"  Cookie '{name}' missing HttpOnly — XSS can steal session")
                self.finding(
                    severity="high",
                    title=f"Cookie '{name}' Missing HttpOnly Flag",
                    description=(
                        f"The session cookie '{name}' does not have the HttpOnly attribute. "
                        "An XSS vulnerability would allow JavaScript to read this cookie and "
                        "hijack the session without any additional exploitation."
                    ),
                    evidence=f"Set-Cookie: {raw[:300]}",
                    cwe="CWE-1004",
                    remediation=(
                        "Set the HttpOnly attribute on all session cookies: "
                        "Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax"
                    ),
                )
                findings_made += 1

            # Secure on HTTPS
            if is_https and not cookie.get("secure") and is_session:
                msg_vuln("medium", f"  Cookie '{name}' missing Secure flag on HTTPS endpoint")
                self.finding(
                    severity="medium",
                    title=f"Cookie '{name}' Missing Secure Flag",
                    description=(
                        f"The session cookie '{name}' does not have the Secure attribute. "
                        "It may be transmitted over unencrypted HTTP connections, exposing it "
                        "to network interception (e.g., MITM on the same network)."
                    ),
                    evidence=f"Set-Cookie: {raw[:300]}",
                    cwe="CWE-614",
                    remediation="Add the Secure flag: Set-Cookie: session=...; Secure",
                )
                findings_made += 1

            # SameSite=None without Secure
            samesite = cookie.get("samesite", "")
            if samesite == "none" and not cookie.get("secure"):
                msg_vuln("medium", f"  Cookie '{name}' SameSite=None without Secure — CSRF risk")
                self.finding(
                    severity="medium",
                    title=f"Cookie '{name}' SameSite=None Without Secure Flag",
                    description=(
                        f"Cookie '{name}' has SameSite=None but lacks the Secure flag. "
                        "Modern browsers reject SameSite=None cookies without Secure, but "
                        "older browsers may send it over HTTP, enabling CSRF attacks."
                    ),
                    evidence=f"Set-Cookie: {raw[:300]}",
                    cwe="CWE-614",
                    remediation="Always pair SameSite=None with the Secure flag.",
                )
                findings_made += 1

            # No SameSite at all
            if "samesite" not in cookie and is_session:
                msg_vuln("low", f"  Cookie '{name}' has no SameSite attribute — CSRF risk")
                self.finding(
                    severity="low",
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    description=(
                        f"Session cookie '{name}' has no SameSite attribute. "
                        "Without SameSite, the cookie is sent on cross-site requests, "
                        "which can enable CSRF attacks in browsers that default to Lax "
                        "only for top-level navigation."
                    ),
                    evidence=f"Set-Cookie: {raw[:300]}",
                    cwe="CWE-1275",
                    remediation="Add SameSite=Lax or SameSite=Strict to session cookies.",
                )
                findings_made += 1

        if findings_made == 0:
            msg_ok(f"  Cookie flags look good ({len(raw_cookies)} cookie(s) checked)")

    # ── Test 2: Session token entropy ─────────────────────────────────────────

    def _test_token_entropy(self) -> None:
        msg_info("Test 2/8 — Session token entropy")
        tokens: list[str] = []
        sample_count = self.options.get("entropy_samples", 7)

        for i in range(sample_count):
            progress_bar(i + 1, sample_count, "collecting tokens")
            try:
                resp = self.tester.get(self.tester.target_url)
            except RequestException:
                continue

            # Collect from Set-Cookie
            raw_cookies = (
                resp.raw.headers.getlist("Set-Cookie")
                if hasattr(resp.raw.headers, "getlist")
                else []
            )
            if not raw_cookies:
                sc = resp.headers.get("Set-Cookie")
                if sc:
                    raw_cookies = [sc]

            for raw in raw_cookies:
                cookie = _parse_set_cookie(raw)
                if _is_session_cookie(cookie.get("name", "")):
                    val = cookie.get("value", "")
                    if val:
                        tokens.append(val)
                        break

            # Also collect from Authorization / auth response body
            try:
                body = resp.json()
                for key in ("token", "access_token", "sessionId", "session_id", "id"):
                    if key in body and isinstance(body[key], str):
                        tokens.append(body[key])
                        break
            except Exception:
                pass

        tokens = list(set(tokens))  # deduplicate

        if len(tokens) < 2:
            msg_info(f"  Only {len(tokens)} distinct token(s) collected — skipping entropy analysis")
            return

        # Check length
        avg_len = sum(len(t) for t in tokens) / len(tokens)
        min_len = min(len(t) for t in tokens)

        if min_len < 16:
            msg_vuln("high", f"  Session tokens very short (min={min_len} chars) — low entropy")
            self.finding(
                severity="high",
                title="Session Token Insufficient Length",
                description=(
                    f"Session tokens have a minimum length of {min_len} characters. "
                    "Short tokens drastically reduce the keyspace and make brute-force "
                    "or guessing attacks feasible."
                ),
                evidence=f"Sample tokens: {tokens[:3]}",
                cwe="CWE-330",
                remediation=(
                    "Use cryptographically secure random tokens of at least 128 bits "
                    "(22+ chars in base64url). Frameworks: secrets.token_urlsafe(32) in Python."
                ),
            )

        # Check sequential pattern
        if _looks_sequential(tokens):
            msg_vuln("critical", "  Tokens appear to be base64(incrementing_int) — CRITICAL")
            self.finding(
                severity="critical",
                title="Session Tokens Are Sequential / Predictable",
                description=(
                    "Session tokens appear to be base64-encoded incrementing integers. "
                    "An attacker can predict valid session IDs for other users and hijack "
                    "their sessions with trivial effort."
                ),
                evidence=f"Token samples: {tokens[:5]}",
                cwe="CWE-330",
                remediation=(
                    "Replace the session ID generator with a CSPRNG. "
                    "Never derive session IDs from sequential counters or timestamps."
                ),
            )
            return

        # Shannon entropy check
        entropy = _token_entropy(tokens)
        msg_info(f"  Token entropy estimate: {entropy:.1f} bits (samples={len(tokens)}, avg_len={avg_len:.1f})")

        if entropy < 40:
            msg_vuln("high", f"  Low token entropy ({entropy:.1f} bits) — tokens may be predictable")
            self.finding(
                severity="high",
                title="Session Token Low Entropy",
                description=(
                    f"Estimated token entropy is {entropy:.1f} bits across {len(tokens)} samples. "
                    "Tokens with insufficient entropy can be guessed or brute-forced."
                ),
                evidence=f"Token samples: {tokens[:3]}",
                cwe="CWE-330",
                remediation=(
                    "Ensure session tokens are generated with a CSPRNG and contain at least "
                    "128 bits of entropy. Avoid time-based or username-derived tokens."
                ),
            )
        else:
            msg_ok(f"  Token entropy looks acceptable ({entropy:.1f} bits)")

    # ── Test 3: Session fixation ───────────────────────────────────────────────

    def _test_session_fixation(self) -> None:
        msg_info("Test 3/8 — Session fixation")
        fabricated = "haakauth_fixation_test_abc123xyz987"

        try:
            resp = self.tester.get(
                self.tester.target_url,
                cookies={"session": fabricated, "PHPSESSID": fabricated,
                         "JSESSIONID": fabricated, "sessionid": fabricated},
            )
        except RequestException as exc:
            msg_warn(f"  Fixation test: request failed — {exc}")
            return

        # Check if any Set-Cookie echoes back our fabricated value
        raw_cookies = (
            resp.raw.headers.getlist("Set-Cookie")
            if hasattr(resp.raw.headers, "getlist")
            else []
        )
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                raw_cookies = [sc]

        reflected = False
        accepted_without_reset = False

        for raw in raw_cookies:
            if fabricated in raw:
                reflected = True
                break

        # If no Set-Cookie issued at all and the server returned 200, it may have
        # accepted our fabricated cookie without regenerating
        if resp.status_code in (200, 302, 301) and not raw_cookies:
            accepted_without_reset = True

        if reflected:
            msg_vuln("high", "  Server echoes back the fabricated session ID — fixation likely")
            self.finding(
                severity="high",
                title="Session Fixation — Server Reflects Attacker-Controlled Session ID",
                description=(
                    "The server accepted a fabricated session cookie value and reflected it "
                    "back in Set-Cookie without generating a new identifier. An attacker can "
                    "set a known session ID, trick the victim into authenticating with it, "
                    "and then use that ID to hijack the session."
                ),
                evidence=f"Sent session={fabricated}, server responded: {raw_cookies[:2]}",
                cwe="CWE-384",
                remediation=(
                    "Always regenerate the session ID after any privilege change or authentication. "
                    "Never accept client-supplied session IDs that don't exist server-side."
                ),
            )
        elif accepted_without_reset:
            msg_vuln("medium", "  Server accepted fabricated session without issuing a new one")
            self.finding(
                severity="medium",
                title="Session Fixation — Server Accepts Unauthenticated Fabricated Session",
                description=(
                    "The server returned 2xx/3xx without issuing a new session cookie when "
                    "presented with a fabricated session ID. This suggests the server may accept "
                    "pre-supplied session identifiers, enabling session fixation."
                ),
                evidence=f"Sent cookies with value={fabricated}, status={resp.status_code}, no new Set-Cookie",
                cwe="CWE-384",
                remediation=(
                    "Regenerate session IDs on every authentication event. "
                    "Reject any session ID that was not issued by the server."
                ),
            )
        else:
            msg_ok("  No session fixation indicators found")

    # ── Test 4: Concurrent session handling ───────────────────────────────────

    def _test_concurrent_sessions(self) -> None:
        msg_info("Test 4/8 — Concurrent session handling")
        status_codes: list[int] = []

        for i in range(3):
            try:
                resp = self.tester.get(self.tester.target_url)
                status_codes.append(resp.status_code)
            except RequestException:
                pass

        if not status_codes:
            msg_warn("  Could not collect concurrent session data")
            return

        all_same = len(set(status_codes)) == 1
        msg_info(
            f"  3 concurrent requests → status codes: {status_codes} "
            f"({'consistent' if all_same else 'inconsistent'})"
        )
        # Informational only — concurrent sessions are allowed by most apps
        if not all_same:
            self.finding(
                severity="info",
                title="Inconsistent Responses on Concurrent Requests",
                description=(
                    "Three sequential requests with the same session token returned different "
                    "HTTP status codes. This may indicate race conditions, session invalidation "
                    "during testing, or load-balancer inconsistencies."
                ),
                evidence=f"Status codes observed: {status_codes}",
                cwe="CWE-362",
                remediation=(
                    "Investigate whether concurrent session access is handled correctly. "
                    "Consider implementing session locking or single-session-per-user policy "
                    "for sensitive applications."
                ),
            )
        else:
            msg_ok("  Concurrent requests handled consistently (informational)")

    # ── Test 5: Logout / token invalidation ───────────────────────────────────

    def _test_logout_invalidation(self) -> None:
        msg_info("Test 5/8 — Logout & token invalidation")

        # Capture the session cookies/headers before logout
        try:
            baseline = self.tester.get(self.tester.target_url)
            session_headers = dict(self.tester.session.headers)
            session_cookies = dict(self.tester.session.cookies)
        except RequestException as exc:
            msg_warn(f"  Logout test: baseline request failed — {exc}")
            return

        # Find a working logout endpoint
        logout_url: str | None = None
        for endpoint in LOGOUT_ENDPOINTS:
            url = self.tester.base_url + endpoint
            try:
                resp = self.tester.get(url)
                if resp.status_code not in (404, 405):
                    logout_url = url
                    msg_info(f"  Found candidate logout endpoint: {endpoint} ({resp.status_code})")
                    break
            except RequestException:
                continue

        if not logout_url:
            msg_info("  No logout endpoint found — skipping token invalidation check")
            return

        # Attempt logout
        try:
            self.tester.post(logout_url)
        except RequestException:
            try:
                self.tester.get(logout_url)
            except RequestException as exc:
                msg_warn(f"  Logout request failed — {exc}")
                return

        # After logout, try to use the original token again
        # Replay with the original session headers/cookies
        try:
            post_logout_resp = self.tester.get(
                self.tester.target_url,
                headers=session_headers,
                cookies=session_cookies,
                allow_redirects=False,
            )
        except RequestException as exc:
            msg_warn(f"  Post-logout validation request failed — {exc}")
            return

        status = post_logout_resp.status_code

        if status in (200, 201, 202):
            msg_vuln("high", f"  Token still valid after logout (status {status}) — session not invalidated")
            self.finding(
                severity="high",
                title="Session Token Not Invalidated After Logout",
                description=(
                    f"After calling {logout_url}, the original session token was replayed and "
                    f"the server responded with HTTP {status}, indicating the token is still valid. "
                    "This allows an attacker who obtains a session token to use it even after "
                    "the legitimate user logs out."
                ),
                evidence=(
                    f"Logout endpoint: {logout_url}\n"
                    f"Post-logout status: {status}\n"
                    f"Response body (first 300 chars): {post_logout_resp.text[:300]}"
                ),
                cwe="CWE-613",
                remediation=(
                    "Invalidate the server-side session on logout. For JWT, maintain a "
                    "token denylist or use short-lived tokens with refresh token revocation."
                ),
            )
        elif status in (401, 403, 302, 307, 308):
            msg_ok(f"  Token correctly invalidated after logout (status {status})")
        else:
            msg_info(f"  Post-logout response status: {status} — inconclusive")

    # ── Test 6: Security headers ───────────────────────────────────────────────

    def _test_security_headers(self) -> None:
        msg_info("Test 6/8 — Security headers audit")
        try:
            resp = self.tester.get(self.tester.target_url)
        except RequestException as exc:
            msg_warn(f"  Security headers: request failed — {exc}")
            return

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing: list[str] = []

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in resp_headers_lower:
                missing.append(header)
                msg_vuln(meta["severity"], f"  Missing: {header} — {meta['description']}")
                self.finding(
                    severity=meta["severity"],
                    title=f"Missing Security Header: {header}",
                    description=meta["description"],
                    evidence=f"Header '{header}' absent from response to GET {self.tester.target_url}",
                    cwe=meta["cwe"],
                    remediation=f"Add '{header}' to all responses. Consult OWASP Secure Headers Project.",
                )

        # Cache-Control on what might be an auth page
        cache_ctrl = resp_headers_lower.get("cache-control", "")
        pragma = resp_headers_lower.get("pragma", "")
        if "no-store" not in cache_ctrl and "no-cache" not in cache_ctrl:
            msg_vuln("medium", "  Cache-Control does not include no-store/no-cache — auth page may be cached")
            self.finding(
                severity="medium",
                title="Authentication Page May Be Cached",
                description=(
                    "The response does not include 'Cache-Control: no-store, no-cache'. "
                    "Shared caches or browser history may store authentication pages and tokens, "
                    "leaking credentials to subsequent users of the same device or proxy."
                ),
                evidence=f"Cache-Control: {cache_ctrl!r}  Pragma: {pragma!r}",
                cwe="CWE-524",
                remediation=(
                    "Set 'Cache-Control: no-store, no-cache, must-revalidate' and "
                    "'Pragma: no-cache' on all authenticated responses."
                ),
            )
            missing.append("Cache-Control: no-store")

        if not missing:
            msg_ok("  All expected security headers are present")
        else:
            msg_info(f"  {len(missing)} missing header(s) found")

    # ── Test 7: CORS configuration ────────────────────────────────────────────

    def _test_cors(self) -> None:
        msg_info("Test 7/8 — CORS configuration")
        findings_made = 0

        for origin in CORS_TEST_ORIGINS:
            try:
                resp = self.tester.options(
                    self.tester.target_url,
                    headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                )
            except RequestException:
                try:
                    resp = self.tester.get(
                        self.tester.target_url,
                        headers={"Origin": origin},
                    )
                except RequestException as exc:
                    msg_warn(f"  CORS test failed for origin {origin} — {exc}")
                    continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == origin and acac == "true":
                msg_vuln("critical", f"  CORS: reflects origin '{origin}' + Allow-Credentials:true — ATO possible")
                self.finding(
                    severity="critical",
                    title="CORS Misconfiguration — Reflected Origin with Credentials",
                    description=(
                        f"The server reflects the attacker-controlled origin '{origin}' in "
                        "Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. "
                        "This allows a malicious website to make credentialed cross-origin requests "
                        "to this API, reading authenticated responses and potentially achieving "
                        "full account takeover."
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    cwe="CWE-942",
                    remediation=(
                        "Never reflect arbitrary Origins. Maintain an explicit allowlist of trusted origins. "
                        "Do not combine wildcard or reflected origins with Allow-Credentials: true."
                    ),
                )
                findings_made += 1

            elif acao == origin:
                msg_vuln("high", f"  CORS: reflects arbitrary origin '{origin}'")
                self.finding(
                    severity="high",
                    title="CORS Misconfiguration — Arbitrary Origin Reflected",
                    description=(
                        f"The server reflects any supplied Origin header in Access-Control-Allow-Origin. "
                        f"Tested with origin '{origin}'. Even without Allow-Credentials, this may expose "
                        "API responses to cross-origin JavaScript in the context of cookies set by "
                        "other means."
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}"
                    ),
                    cwe="CWE-942",
                    remediation=(
                        "Use a static allowlist for trusted origins. "
                        "Avoid dynamically reflecting the Origin header."
                    ),
                )
                findings_made += 1

            elif acao == "*":
                msg_vuln("medium", "  CORS: Access-Control-Allow-Origin: * (wildcard)")
                self.finding(
                    severity="medium",
                    title="CORS Wildcard Allow-Origin",
                    description=(
                        "The server sets Access-Control-Allow-Origin: * which allows any origin "
                        "to read the response. This is acceptable for fully public resources but "
                        "problematic if the endpoint returns any user-specific data."
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    cwe="CWE-942",
                    remediation=(
                        "Replace the wildcard with an explicit list of trusted origins "
                        "for any endpoint that returns sensitive or user-specific data."
                    ),
                )
                findings_made += 1
                break  # wildcard is the same for all origins

        if findings_made == 0:
            msg_ok("  CORS configuration looks correct for tested origins")

    # ── Test 8: Token in URL ───────────────────────────────────────────────────

    def _test_token_in_url(self) -> None:
        msg_info("Test 8/8 — Token in URL / Referer leakage")
        try:
            resp = self.tester.get(self.tester.target_url)
        except RequestException as exc:
            msg_warn(f"  Token-in-URL: request failed — {exc}")
            return

        parsed = urlparse(resp.url)
        query = parsed.query
        fragment = parsed.fragment

        token_param_patterns = re.compile(
            r"(token|access_token|auth|jwt|session|sid|apikey|api_key|key|secret)=([^&]+)",
            re.IGNORECASE,
        )

        findings_made = False

        # Check URL query string
        match = token_param_patterns.search(query)
        if match:
            msg_vuln("medium", f"  Auth token found in URL query string: param '{match.group(1)}'")
            self.finding(
                severity="medium",
                title="Authentication Token Exposed in URL Query String",
                description=(
                    f"The authentication token parameter '{match.group(1)}' appears in the URL "
                    "query string. Query parameters are logged in browser history, server logs, "
                    "proxy logs, and Referer headers, leading to token exposure."
                ),
                evidence=f"URL: {resp.url[:300]}",
                cwe="CWE-598",
                remediation=(
                    "Transmit tokens exclusively via HTTP headers (Authorization: Bearer <token>) "
                    "or cookies with appropriate security flags. Never embed tokens in URLs."
                ),
            )
            findings_made = True

        # Check URL fragment (rare, but worth noting)
        if fragment and token_param_patterns.search(fragment):
            msg_vuln("low", "  Auth token found in URL fragment")
            self.finding(
                severity="low",
                title="Authentication Token Exposed in URL Fragment",
                description=(
                    "An authentication token was found in the URL fragment (#). "
                    "While fragments are not sent to servers, they are visible in browser history "
                    "and may leak via JavaScript."
                ),
                evidence=f"Fragment: #{fragment[:200]}",
                cwe="CWE-598",
                remediation="Avoid placing sensitive tokens in URL fragments.",
            )
            findings_made = True

        # Check Referer header leakage potential: if the page links to third-party resources
        # and has no Referrer-Policy, the token in URL leaks via Referer
        referer_policy = resp.headers.get("Referrer-Policy", "")
        if not referer_policy and match:
            msg_vuln("medium", "  No Referrer-Policy — token in URL may leak via Referer header")
            self.finding(
                severity="medium",
                title="Token in URL May Leak via Referer Header (No Referrer-Policy)",
                description=(
                    "The page contains an authentication token in the URL and has no Referrer-Policy. "
                    "If this page links to any external resource, the token will be sent in the "
                    "Referer header to the third-party server."
                ),
                evidence=f"URL: {resp.url[:300]}\nReferrer-Policy: (absent)",
                cwe="CWE-200",
                remediation=(
                    "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin' "
                    "and stop embedding tokens in URLs."
                ),
            )
            findings_made = True

        if not findings_made:
            msg_ok("  No token-in-URL or Referer leakage indicators found")
