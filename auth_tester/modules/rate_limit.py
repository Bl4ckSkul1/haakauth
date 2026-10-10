"""
rate_limit.py — Rate limiting and brute force protection testing module.

Tests:
  1. Login endpoint rate limit
  2. Account lockout
  3. OTP / MFA brute force protection
  4. Username enumeration (response-based + timing-based)
  5. Password reset rate limit
  6. Generic API endpoint rate limit
  7. IP rotation bypass via X-Forwarded-For
"""
from __future__ import annotations

import time
import statistics
import re
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException, ConnectionError as ReqConnError, Timeout

from auth_tester.core import BaseModule, AuthTester
from auth_tester.colors import (
    msg_info, msg_ok, msg_fail, msg_vuln, msg_warn, section, progress_bar,
)
from auth_tester.data.payloads import PASSWORD_RESET_ENDPOINTS
from auth_tester.data.common_passwords import TOP_USERNAMES


# ── constants ─────────────────────────────────────────────────────────────────

_OTP_URL_PATTERNS = re.compile(
    r"(otp|mfa|2fa|verify|one.?time|totp|code|token|confirm)",
    re.IGNORECASE,
)

_OTP_PARAM_PATTERNS = re.compile(
    r"^(otp|code|mfa|2fa|token|pin|verify|passcode)$",
    re.IGNORECASE,
)

_RATE_LIMIT_STATUS = {429, 423, 503}
_CAPTCHA_PATTERNS = re.compile(
    r"(captcha|recaptcha|hcaptcha|turnstile|bot.detect|challenge)",
    re.IGNORECASE,
)
_LOCKOUT_PATTERNS = re.compile(
    r"(account.locked|too.many.attempt|locked.out|temporarily.disabled|banned|blocked)",
    re.IGNORECASE,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_rate_limited(resp: requests.Response) -> bool:
    """Return True if response indicates rate limiting / throttling."""
    if resp.status_code in _RATE_LIMIT_STATUS:
        return True
    body = ""
    try:
        body = resp.text
    except Exception:
        pass
    if _CAPTCHA_PATTERNS.search(body):
        return True
    if _LOCKOUT_PATTERNS.search(body):
        return True
    return False


def _is_lockout(resp: requests.Response) -> bool:
    """Return True if response indicates account lockout."""
    try:
        body = resp.text
    except Exception:
        return False
    return bool(_LOCKOUT_PATTERNS.search(body)) or resp.status_code == 423


def _resp_signature(resp: requests.Response) -> tuple:
    """Return a tuple that characterises a response for comparison."""
    try:
        body = resp.text
    except Exception:
        body = ""
    # Strip tokens/UUIDs from body to normalise it
    body_norm = re.sub(r"[0-9a-fA-F\-]{16,}", "<TOKEN>", body)
    return (resp.status_code, len(body), body_norm[:200])


def _xforward_headers(ip: str) -> dict:
    return {"X-Forwarded-For": ip, "X-Real-IP": ip, "True-Client-IP": ip}


# ── module ────────────────────────────────────────────────────────────────────

class RateLimitModule(BaseModule):
    NAME = "rate_limit"
    DESCRIPTION = "Rate limiting and brute force protection testing"

    # Options consumed:
    #   burst_count   int   — rapid requests to fire (default 20)
    #   username      str   — target username for login/lockout tests
    #   password      str   — wrong password for login tests
    #   wordlist      str   — path to username list for enumeration

    def run(self) -> None:
        section("Rate Limit & Brute Force Protection")

        self._test_login_rate_limit()
        self._test_account_lockout()
        self._test_otp_brute_force()
        self._test_username_enumeration()
        self._test_password_reset_rate_limit()
        self._test_api_rate_limit()
        self._test_xff_bypass()

    # ── Test 1: Login endpoint rate limit ─────────────────────────────────────

    def _test_login_rate_limit(self) -> None:
        msg_info("Test 1/7 — Login endpoint rate limit")
        burst = self.options.get("burst_count", 20)
        username = self.options.get("username", "admin")
        wrong_pass = self.options.get("password", "WrongPass123!")
        url = self.tester.target_url

        responses: list[requests.Response] = []
        timings: list[float] = []
        rate_limited_at: int | None = None

        original_delay = self.tester.delay
        self.tester.delay = 0.0  # fire rapidly

        try:
            for i in range(burst):
                progress_bar(i + 1, burst, "sending requests")
                t0 = time.monotonic()
                try:
                    resp = self.tester.post(
                        url,
                        json={"username": username, "password": wrong_pass},
                        allow_redirects=False,
                    )
                    elapsed = time.monotonic() - t0
                    timings.append(elapsed)
                    responses.append(resp)

                    if _is_rate_limited(resp):
                        rate_limited_at = i + 1
                        msg_info(f"\n  Rate limiting triggered at request #{rate_limited_at}")
                        break
                except (RequestException, Timeout):
                    timings.append(0.0)
        finally:
            self.tester.delay = original_delay

        if not responses:
            msg_warn("  No responses collected for login rate limit test")
            return

        if rate_limited_at:
            msg_ok(f"  Rate limiting active — triggered after {rate_limited_at} requests")
            return

        # Check if all responses look the same (no throttling detected)
        sigs = [_resp_signature(r) for r in responses]
        all_same_status = len({r.status_code for r in responses}) == 1
        any_increasing_delay = False

        if len(timings) > 4:
            first_half = timings[:len(timings) // 2]
            second_half = timings[len(timings) // 2:]
            avg_first = statistics.mean(first_half)
            avg_second = statistics.mean(second_half)
            if avg_second > avg_first * 2 and avg_second > 0.5:
                any_increasing_delay = True
                msg_info(f"  Server-side throttling detected (avg latency: {avg_first:.2f}s → {avg_second:.2f}s)")

        if all_same_status and not any_increasing_delay:
            msg_vuln("high", f"  No rate limiting detected after {burst} rapid login attempts")
            self.finding(
                severity="high",
                title="No Rate Limiting on Login Endpoint",
                description=(
                    f"The login endpoint accepted {burst} consecutive failed attempts without "
                    "returning HTTP 429, triggering CAPTCHA, or showing increasing response delays. "
                    "This allows automated brute-force attacks against user passwords."
                ),
                evidence=(
                    f"Target: {url}\n"
                    f"Requests sent: {burst}\n"
                    f"Status codes: {list(set(r.status_code for r in responses))}\n"
                    f"Avg response time: {statistics.mean(timings):.3f}s"
                ),
                cwe="CWE-307",
                remediation=(
                    "Implement rate limiting on the login endpoint (e.g., 5 attempts per IP per minute). "
                    "Consider account lockout after N failures, exponential back-off, or CAPTCHA. "
                    "Tools: fail2ban, nginx limit_req, Spring Security, rack-attack."
                ),
            )
        elif any_increasing_delay:
            msg_ok("  Server-side throttling (increasing delay) detected")
        else:
            msg_ok(f"  Rate limiting behaviour observed ({burst} requests)")

    # ── Test 2: Account lockout ────────────────────────────────────────────────

    def _test_account_lockout(self) -> None:
        msg_info("Test 2/7 — Account lockout testing")
        username = self.options.get("username", "admin")
        wrong_pass = self.options.get("password", "WrongPass123!")
        url = self.tester.target_url
        attempts = 10

        original_delay = self.tester.delay
        self.tester.delay = 0.3  # slight delay to avoid IP ban mid-test

        locked = False
        last_resp: requests.Response | None = None

        try:
            for i in range(attempts):
                progress_bar(i + 1, attempts, "failed login attempts")
                try:
                    resp = self.tester.post(
                        url,
                        json={"username": username, "password": wrong_pass},
                        allow_redirects=False,
                    )
                    last_resp = resp
                    if _is_lockout(resp):
                        locked = True
                        msg_info(f"\n  Account lockout triggered at attempt #{i + 1}")
                        break
                    if _is_rate_limited(resp):
                        msg_info(f"\n  Rate limiting (not lockout) triggered at attempt #{i + 1}")
                        return
                except RequestException:
                    pass
        finally:
            self.tester.delay = original_delay

        if locked:
            msg_ok("  Account lockout mechanism is active")
        else:
            msg_vuln("medium", f"  No account lockout after {attempts} failed login attempts")
            evidence_body = ""
            if last_resp is not None:
                try:
                    evidence_body = last_resp.text[:300]
                except Exception:
                    pass
            self.finding(
                severity="medium",
                title="No Account Lockout After Repeated Failed Logins",
                description=(
                    f"The application did not lock or throttle the account '{username}' "
                    f"after {attempts} consecutive failed login attempts. Combined with no "
                    "rate limiting, this exposes accounts to sustained brute-force attacks."
                ),
                evidence=(
                    f"Target: {url}\n"
                    f"Username tested: {username}\n"
                    f"Failed attempts: {attempts}\n"
                    f"Last response body: {evidence_body}"
                ),
                cwe="CWE-307",
                remediation=(
                    "Implement account lockout after 5-10 failed attempts. "
                    "Prefer soft lockout (time-based: 15 min) over hard lockout to avoid DoS. "
                    "Notify the account owner on lockout."
                ),
            )

    # ── Test 3: OTP / MFA brute force ─────────────────────────────────────────

    def _test_otp_brute_force(self) -> None:
        msg_info("Test 3/7 — OTP / MFA brute force protection")
        url = self.tester.target_url

        # Determine if this looks like an OTP endpoint
        parsed = urlparse(url)
        path_looks_like_otp = bool(_OTP_URL_PATTERNS.search(parsed.path))
        if not path_looks_like_otp:
            msg_info("  URL does not look like an OTP/MFA endpoint — skipping OTP test")
            return

        burst = self.options.get("burst_count", 20)
        rate_limited_at: int | None = None
        responses: list[requests.Response] = []

        original_delay = self.tester.delay
        self.tester.delay = 0.0

        try:
            for i in range(burst):
                progress_bar(i + 1, burst, "OTP attempts")
                # Generate 4-6 digit codes
                code = str(i * 3 + 1001).zfill(6)
                try:
                    resp = self.tester.post(
                        url,
                        json={"code": code, "otp": code, "token": code},
                        allow_redirects=False,
                    )
                    responses.append(resp)

                    if _is_rate_limited(resp):
                        rate_limited_at = i + 1
                        msg_info(f"\n  OTP rate limiting triggered at attempt #{rate_limited_at}")
                        break
                    if _is_lockout(resp):
                        msg_ok(f"\n  OTP lockout triggered at attempt #{i + 1}")
                        return
                except RequestException:
                    pass
        finally:
            self.tester.delay = original_delay

        if not responses:
            msg_warn("  No OTP test responses collected")
            return

        if rate_limited_at:
            msg_ok(f"  OTP rate limit active (triggered at {rate_limited_at})")
            return

        msg_vuln("critical", f"  No OTP rate limiting after {burst} attempts — brute force feasible")
        self.finding(
            severity="critical",
            title="No Rate Limiting on OTP / MFA Verification Endpoint",
            description=(
                f"The MFA/OTP verification endpoint at '{url}' accepted {burst} consecutive "
                "attempts without rate limiting, CAPTCHA, or lockout. "
                "A 4-digit OTP has only 10,000 combinations; a 6-digit OTP has 1,000,000. "
                "Without rate limiting, an attacker can enumerate all possible OTP values "
                "within minutes to bypass multi-factor authentication entirely."
            ),
            evidence=(
                f"Target: {url}\n"
                f"Attempts: {burst}\n"
                f"Status codes observed: {list(set(r.status_code for r in responses))}"
            ),
            cwe="CWE-307",
            remediation=(
                "Apply strict rate limiting to OTP endpoints: maximum 3-5 attempts, "
                "then lock for 15-30 minutes. Bind OTP attempts to the authenticated session "
                "in addition to IP-based rate limiting."
            ),
        )

    # ── Test 4: Username enumeration ──────────────────────────────────────────

    def _test_username_enumeration(self) -> None:
        msg_info("Test 4/7 — Username enumeration")
        url = self.tester.target_url
        wrong_pass = self.options.get("password", "WrongPass123!")

        # Build username list
        wordlist_path = self.options.get("wordlist")
        usernames: list[str] = []
        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
                    usernames = [line.strip() for line in fh if line.strip()][:20]
            except OSError as exc:
                msg_warn(f"  Could not read wordlist '{wordlist_path}': {exc}")

        if not usernames:
            # Use built-in: mix of likely-real and definitely-fake
            usernames = [
                "admin",
                "administrator",
                "nonexistent_haakauth_xyz_99999",
                "this_user_absolutely_does_not_exist_haak",
            ]

        results: dict[str, dict] = {}
        original_delay = self.tester.delay
        self.tester.delay = 0.2

        try:
            for i, uname in enumerate(usernames[:10]):
                progress_bar(i + 1, min(len(usernames), 10), uname)
                t0 = time.monotonic()
                try:
                    resp = self.tester.post(
                        url,
                        json={"username": uname, "password": wrong_pass},
                        allow_redirects=False,
                    )
                    elapsed = time.monotonic() - t0
                    body = ""
                    try:
                        body = resp.text[:500]
                    except Exception:
                        pass
                    results[uname] = {
                        "status": resp.status_code,
                        "length": len(body),
                        "elapsed": elapsed,
                        "body_snippet": body[:150],
                    }
                except RequestException as exc:
                    results[uname] = {"status": 0, "length": 0, "elapsed": 0.0, "body_snippet": str(exc)}
        finally:
            self.tester.delay = original_delay

        if len(results) < 2:
            msg_warn("  Insufficient enumeration data collected")
            return

        values = list(results.values())

        # Compare status codes
        statuses = {u: d["status"] for u, d in results.items()}
        unique_statuses = set(statuses.values()) - {0}

        if len(unique_statuses) > 1:
            msg_vuln("medium", "  Different HTTP status codes for different usernames — enumeration possible")
            self.finding(
                severity="medium",
                title="Username Enumeration via Different HTTP Status Codes",
                description=(
                    "The login endpoint returns different HTTP status codes depending on whether "
                    "the username exists. An attacker can enumerate valid accounts by observing "
                    "these differences."
                ),
                evidence="\n".join(f"  {u}: HTTP {d['status']}" for u, d in results.items()),
                cwe="CWE-204",
                remediation=(
                    "Return a uniform HTTP status code (e.g., 401) for all authentication failures "
                    "regardless of whether the username exists."
                ),
            )

        # Compare response bodies for revealing messages
        bodies = {u: d["body_snippet"].lower() for u, d in results.items()}
        enum_msgs = {
            "invalid username": "username-revealing error message",
            "user not found": "username-revealing error message",
            "no account": "username-revealing error message",
            "email not registered": "username-revealing error message",
            "incorrect password": "password-specific error (implies username is valid)",
            "wrong password": "password-specific error (implies username is valid)",
        }
        body_enum_found: list[str] = []
        for u, body in bodies.items():
            for phrase, reason in enum_msgs.items():
                if phrase in body:
                    body_enum_found.append(f"User '{u}' response contains '{phrase}' ({reason})")

        if body_enum_found:
            msg_vuln("medium", "  Response body reveals username validity — enumeration via error messages")
            self.finding(
                severity="medium",
                title="Username Enumeration via Different Error Messages",
                description=(
                    "The application returns different error messages depending on whether "
                    "the submitted username exists, enabling username enumeration."
                ),
                evidence="\n".join(body_enum_found),
                cwe="CWE-204",
                remediation=(
                    "Use a generic error message for all authentication failures, e.g.: "
                    "'Invalid username or password.' Never confirm or deny whether a username exists."
                ),
            )

        # Timing-based enumeration
        timings = {u: d["elapsed"] for u, d in results.items() if d["elapsed"] > 0}
        if len(timings) >= 2:
            elapsed_values = list(timings.values())
            max_diff = max(elapsed_values) - min(elapsed_values)
            if max_diff > 0.1:
                msg_vuln("low", f"  Timing difference {max_diff*1000:.0f}ms between usernames — timing-based enumeration")
                self.finding(
                    severity="low",
                    title="Username Enumeration via Response Timing",
                    description=(
                        f"Response times differ by up to {max_diff*1000:.0f}ms across usernames. "
                        "This may indicate that the server performs additional work (e.g., password "
                        "hashing) only for valid usernames, leaking their existence via timing."
                    ),
                    evidence="\n".join(f"  {u}: {t*1000:.0f}ms" for u, t in timings.items()),
                    cwe="CWE-208",
                    remediation=(
                        "Apply constant-time comparison for authentication checks. "
                        "Always perform the password hash operation regardless of whether the "
                        "username exists (use a dummy hash for non-existent users)."
                    ),
                )
            else:
                msg_ok("  No significant timing differences observed between usernames")

        if len(unique_statuses) <= 1 and not body_enum_found:
            msg_ok("  No obvious username enumeration indicators found")

    # ── Test 5: Password reset rate limit ─────────────────────────────────────

    def _test_password_reset_rate_limit(self) -> None:
        msg_info("Test 5/7 — Password reset rate limit")
        burst = self.options.get("burst_count", 10)
        test_email = "haakauth-test@example.com"
        reset_url: str | None = None

        # Probe common reset endpoints
        for endpoint in PASSWORD_RESET_ENDPOINTS:
            url = self.tester.base_url + endpoint
            try:
                resp = self.tester.post(
                    url,
                    json={"email": test_email},
                    allow_redirects=False,
                )
                if resp.status_code not in (404, 405, 501):
                    reset_url = url
                    msg_info(f"  Found password reset endpoint: {endpoint} ({resp.status_code})")
                    break
            except RequestException:
                continue

        if not reset_url:
            # Try GET as well (some frameworks use GET for forgot-password page)
            for endpoint in PASSWORD_RESET_ENDPOINTS[:5]:
                url = self.tester.base_url + endpoint
                try:
                    resp = self.tester.get(url, allow_redirects=False)
                    if resp.status_code not in (404,):
                        reset_url = url
                        break
                except RequestException:
                    continue

        if not reset_url:
            msg_info("  No password reset endpoint found — skipping")
            return

        responses: list[requests.Response] = []
        rate_limited_at: int | None = None
        original_delay = self.tester.delay
        self.tester.delay = 0.0

        try:
            for i in range(burst):
                progress_bar(i + 1, burst, "reset requests")
                try:
                    resp = self.tester.post(
                        reset_url,
                        json={"email": test_email},
                        allow_redirects=False,
                    )
                    responses.append(resp)
                    if _is_rate_limited(resp):
                        rate_limited_at = i + 1
                        break
                except RequestException:
                    pass
        finally:
            self.tester.delay = original_delay

        if not responses:
            msg_warn("  No responses from reset endpoint")
            return

        if rate_limited_at:
            msg_ok(f"  Rate limiting on reset endpoint (triggered at {rate_limited_at})")
            return

        msg_vuln("medium", f"  No rate limiting on password reset — email bombing possible")
        self.finding(
            severity="medium",
            title="No Rate Limiting on Password Reset Endpoint",
            description=(
                f"The password reset endpoint '{reset_url}' accepted {len(responses)} consecutive "
                "requests for the same email address without rate limiting. This enables: "
                "(1) Email bombing / spam to victim addresses. "
                "(2) Enumeration of registered email addresses via response differences. "
                "(3) Token flooding to reduce effective entropy of reset links."
            ),
            evidence=(
                f"Target: {reset_url}\n"
                f"Requests sent: {len(responses)}\n"
                f"Status codes: {list(set(r.status_code for r in responses))}"
            ),
            cwe="CWE-307",
            remediation=(
                "Rate limit password reset requests per email address (e.g., 3 per hour) "
                "and per IP (e.g., 10 per hour). Return a generic message regardless of whether "
                "the email exists."
            ),
        )

    # ── Test 6: Generic API rate limit ────────────────────────────────────────

    def _test_api_rate_limit(self) -> None:
        msg_info("Test 6/7 — API endpoint rate limit (50 rapid requests)")
        url = self.tester.target_url
        total = 50
        responses: list[requests.Response] = []
        timings: list[float] = []
        rate_limited_at: int | None = None

        original_delay = self.tester.delay
        self.tester.delay = 0.0

        try:
            for i in range(total):
                progress_bar(i + 1, total, "probing")
                t0 = time.monotonic()
                try:
                    resp = self.tester.get(url, allow_redirects=False)
                    elapsed = time.monotonic() - t0
                    responses.append(resp)
                    timings.append(elapsed)

                    if _is_rate_limited(resp):
                        rate_limited_at = i + 1
                        msg_info(f"\n  Rate limiting triggered at request #{rate_limited_at}")
                        break
                except Timeout:
                    # Server-imposed timeout counts as throttling
                    rate_limited_at = i + 1
                    msg_info(f"\n  Timeout at request #{i + 1} — server may be throttling")
                    break
                except RequestException:
                    pass
        finally:
            self.tester.delay = original_delay

        if not responses:
            msg_warn("  No responses collected for API rate limit test")
            return

        if rate_limited_at:
            elapsed_avg = statistics.mean(timings) if timings else 0
            rps = rate_limited_at / max(sum(timings[:rate_limited_at]), 0.001)
            msg_ok(f"  Rate limiting active — {rate_limited_at} req before throttle ({rps:.1f} req/s)")
            return

        # No rate limiting found
        total_time = sum(timings)
        rps = len(responses) / max(total_time, 0.001)
        msg_vuln("low", f"  No rate limiting: {total} requests at {rps:.1f} req/s without throttle")
        self.finding(
            severity="low",
            title="No Rate Limiting on API Endpoint",
            description=(
                f"The endpoint '{url}' handled {total} rapid requests ({rps:.1f} req/s) "
                "without any rate limiting response. While this may be intentional for public "
                "endpoints, the absence of rate limiting exposes the server to resource exhaustion "
                "and enables enumeration or scraping attacks."
            ),
            evidence=(
                f"Target: {url}\n"
                f"Requests: {total}\n"
                f"Average RPS: {rps:.1f}\n"
                f"Elapsed: {total_time:.2f}s"
            ),
            cwe="CWE-770",
            remediation=(
                "Apply rate limiting on all API endpoints. Recommended thresholds depend on use case; "
                "common defaults: 60-100 req/min per IP for authenticated, 20-30 for unauthenticated. "
                "Tools: nginx limit_req, API Gateway throttling, express-rate-limit, Django Ratelimit."
            ),
        )

    # ── Test 7: X-Forwarded-For rate limit bypass ─────────────────────────────

    def _test_xff_bypass(self) -> None:
        msg_info("Test 7/7 — IP rotation bypass via X-Forwarded-For")
        url = self.tester.target_url
        wrong_pass = self.options.get("password", "WrongPass123!")
        username = self.options.get("username", "admin")

        # First, establish a baseline to see if we get rate limited at all
        # Send 5 requests without spoofing to get a baseline status
        baseline_statuses: list[int] = []
        original_delay = self.tester.delay
        self.tester.delay = 0.0

        try:
            for _ in range(5):
                try:
                    resp = self.tester.post(
                        url,
                        json={"username": username, "password": wrong_pass},
                        allow_redirects=False,
                    )
                    baseline_statuses.append(resp.status_code)
                    if _is_rate_limited(resp):
                        break
                except RequestException:
                    pass
        finally:
            self.tester.delay = original_delay

        if not baseline_statuses:
            msg_warn("  XFF bypass: no baseline responses — skipping")
            return

        baseline_rate_limited = any(s in _RATE_LIMIT_STATUS for s in baseline_statuses)

        # Now test with varying X-Forwarded-For
        test_ips = [
            f"192.168.{i}.{j}" for i in range(1, 4) for j in range(1, 6)
        ][:10]

        xff_statuses: list[int] = []
        original_delay = self.tester.delay
        self.tester.delay = 0.0

        try:
            for i, ip in enumerate(test_ips):
                progress_bar(i + 1, len(test_ips), f"XFF: {ip}")
                try:
                    resp = self.tester.post(
                        url,
                        json={"username": username, "password": wrong_pass},
                        headers=_xforward_headers(ip),
                        allow_redirects=False,
                    )
                    xff_statuses.append(resp.status_code)
                except RequestException:
                    xff_statuses.append(0)
        finally:
            self.tester.delay = original_delay

        if not xff_statuses:
            msg_warn("  XFF bypass: no responses collected")
            return

        xff_rate_limited = any(s in _RATE_LIMIT_STATUS for s in xff_statuses)

        # If baseline was rate-limited but XFF was not → bypass confirmed
        if baseline_rate_limited and not xff_rate_limited:
            msg_vuln("high", "  X-Forwarded-For bypasses rate limiting — WAF/rate-limit trusts XFF")
            self.finding(
                severity="high",
                title="Rate Limit Bypass via X-Forwarded-For Header",
                description=(
                    "The application's rate limiting mechanism trusts the X-Forwarded-For header "
                    "to identify the client IP. By rotating the XFF header value, an attacker can "
                    "bypass rate limits and perform unlimited brute-force or enumeration attacks "
                    "from a single IP address."
                ),
                evidence=(
                    f"Baseline (no XFF) statuses: {baseline_statuses}\n"
                    f"With varied X-Forwarded-For: {xff_statuses}\n"
                    f"IPs tested: {test_ips[:5]}"
                ),
                cwe="CWE-290",
                remediation=(
                    "Never solely trust X-Forwarded-For for rate limiting decisions. "
                    "Use the real TCP connection IP as the primary identifier. "
                    "If behind a trusted reverse proxy, only accept XFF from known proxy IPs "
                    "and validate the header against a whitelist."
                ),
            )
        elif not baseline_rate_limited:
            # No rate limiting at all, already reported in test 1/6
            msg_info("  XFF bypass: no rate limiting baseline to bypass (see tests 1 and 6)")
        else:
            msg_ok("  Rate limiting is not bypassable via X-Forwarded-For")
