# HaakAuth

```
██╗  ██╗ █████╗  █████╗ ██╗  ██╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
███████║███████║███████║█████╔╝ ███████║██║   ██║   ██║   ███████║
██╔══██║██╔══██║██╔══██║██╔═██╗ ██╔══██║██║   ██║   ██║   ██╔══██║
██║  ██║██║  ██║██║  ██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

  Authentication & Authorization Security Tester
  By Adrian Martinez | HAAK Cybersecurity
```

**Automated authentication and authorization security testing for pentesters.**

HaakAuth tests JWT security, IDOR/BOLA vulnerabilities, authentication bypass techniques, session management, and rate limiting — all from a single command. Supports Burp Suite request import and generates professional HTML reports.

---

## Features

### JWT Attacks
- Algorithm None (4 variants)
- Algorithm confusion (RS256 → HS256)
- Expired token replay
- Claim tampering (role escalation, admin injection)
- Missing/empty signature
- Header injection (KID path traversal + SQLi, JKU/X5U SSRF)
- Blank/null token testing
- Token location testing (header, cookie, query param)

### IDOR / BOLA Detection
- Auto-detect ID parameters in URL, query, and JSON body
- Numeric ID manipulation (N±1, N±2, 0, 1, -1, 999999)
- UUID/GUID manipulation
- Cross-account access testing (with second token)
- Method-based IDOR (GET→PUT/DELETE escalation)
- Parameter pollution (duplicate params, arrays)
- Encoding bypass (URL encode, hex, base64)

### Authentication Bypass
- HTTP method switching (GET/POST/PUT/PATCH/DELETE/OPTIONS)
- Path traversal bypass (14 patterns: `/../`, `//`, `%2f`, `..;/`)
- Header-based bypass (21 headers: X-Forwarded-For, X-Original-URL, etc.)
- Auth header removal/manipulation
- Method override headers
- Content-Type switching
- API version bypass (v0, v1, v2, /internal/)
- Default credential testing (15 common pairs)

### Session Security Audit
- Cookie flags (HttpOnly, Secure, SameSite)
- Session token entropy analysis
- Session fixation testing
- Logout token invalidation
- Security headers audit (HSTS, CSP, X-Frame-Options, etc.)
- CORS misconfiguration detection
- Token in URL leakage

### Rate Limiting
- Login brute force detection
- Account lockout testing
- OTP/MFA brute force
- Username enumeration (response diff + timing)
- Password reset rate limiting
- API endpoint rate limiting
- X-Forwarded-For bypass detection

---

## Quick Start

### Install

```bash
git clone https://github.com/Bl4ckSkul1/haakauth.git
cd haakauth
pip install requests
```

### Basic Usage

```bash
# Test a URL with a Bearer token
python haakauth.py -u https://api.target.com/me -t "Bearer eyJhbG..."

# Test all modules
python haakauth.py -u https://api.target.com/me -t "Bearer eyJ..." --all

# Specific modules only
python haakauth.py -u https://api.target.com/me -t "Bearer eyJ..." --modules jwt,idor

# Import from Burp Suite
python haakauth.py -p burp_request.txt --all
```

### IDOR Testing with Two Accounts

```bash
python haakauth.py -u https://api.target.com/api/users/123 \
  -t "Bearer token_account_A" \
  --token2 "Bearer token_account_B" \
  --idor
```

### Rate Limit Testing

```bash
python haakauth.py -u https://target.com/login \
  --rate-limit \
  --wordlist usernames.txt
```

### Generate HTML Report

```bash
python haakauth.py -u https://api.target.com/me -t "Bearer eyJ..." \
  --all \
  -o results.json \
  --html report.html \
  --engagement HAAK-2026-004
```

---

## All Options

```
python haakauth.py [options]

TARGET:
  -u, --url URL            Target URL
  -p, --peticion FILE      Burp Suite request file

AUTHENTICATION:
  -t, --token TOKEN        Auth token (Bearer, Basic, or raw)
  -c, --cookie COOKIE      Session cookie(s)
  -H, --header HEADER      Custom header (repeatable)

SECOND ACCOUNT (IDOR):
  --token2 TOKEN           Second account token for cross-account IDOR
  --cookie2 COOKIE         Second account cookie

MODULES:
  --all                    Run all modules
  --modules LIST           Comma-separated: jwt,idor,bypass,session,rate
  --jwt                    JWT attacks only
  --idor                   IDOR detection only
  --bypass                 Auth bypass only
  --session                Session audit only
  --rate-limit             Rate limiting test only

IDOR OPTIONS:
  --id-param NAME          Parameter name for IDOR (auto-detect if omitted)
  --id-range RANGE         ID range to test (e.g., 1-100)

RATE LIMIT OPTIONS:
  --wordlist FILE          Username wordlist for brute force testing
  --password PASS          Password for rate limit testing (default: WrongPass123!)

CONNECTION:
  --proxy URL              HTTP proxy (e.g., http://127.0.0.1:8080)
  --delay SECONDS          Delay between requests (default: 0.5)
  --timeout SECONDS        Request timeout (default: 15)
  --threads N              Concurrent threads (default: 10)

OUTPUT:
  -o, --output FILE        JSON report output
  --html FILE              HTML report output
  --engagement ID          Engagement ID for report
  -q, --quiet              Minimal output
```

---

## Burp Suite Integration

Copy any request from Burp Repeater to a file:

```
GET /api/users/me HTTP/2
Host: api.target.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json
Cookie: session=abc123
```

```bash
python haakauth.py -p request.txt --all -o results.json --html report.html
```

HaakAuth auto-detects:
- HTTP method, URL, and headers
- Authentication type (Bearer, Basic, Cookie, API Key)
- Content-Type and body format
- Injection points in JSON/form bodies

---

## HTML Report

The report includes:
- **Executive Summary** with severity breakdown cards
- **Risk Score Gauge** (0-100) with visual meter
- **Findings by Module** stacked bar chart
- **Detailed Findings** with request/response evidence, CWE references, and remediation
- **Module Details** with test results per module
- **Methodology** section

Dark theme with HAAK branding. Self-contained HTML, no external dependencies.

---

## Project Structure

```
haakauth/
├── haakauth.py                    # Entry point
├── haakauth_report.py             # HTML report generator
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
├── .gitignore
└── auth_tester/
    ├── __init__.py
    ├── main.py                    # CLI orchestrator
    ├── core.py                    # HTTP engine, Finding, BaseModule
    ├── colors.py                  # Terminal output formatting
    ├── request_parser.py          # Burp request parser
    ├── modules/
    │   ├── __init__.py            # Module registry
    │   ├── jwt_attacks.py         # JWT security testing
    │   ├── idor_detector.py       # IDOR/BOLA detection
    │   ├── auth_bypass.py         # Auth bypass techniques
    │   ├── session_audit.py       # Session management audit
    │   └── rate_limit.py          # Rate limiting tests
    └── data/
        ├── __init__.py
        ├── payloads.py            # Attack payloads and test vectors
        └── common_passwords.py    # Default credentials wordlist
```

---

## CWE Coverage

| CWE | Description | Module |
|-----|-------------|--------|
| CWE-22 | Path Traversal | bypass |
| CWE-204 | Observable Response Discrepancy | rate |
| CWE-235 | Improper Handling of Extra Parameters | idor |
| CWE-284 | Improper Access Control | jwt |
| CWE-287 | Improper Authentication | bypass |
| CWE-290 | Authentication Bypass by Spoofing | bypass |
| CWE-306 | Missing Authentication | jwt, bypass |
| CWE-307 | Brute Force | rate |
| CWE-327 | Broken Crypto Algorithm | jwt |
| CWE-330 | Insufficient Randomness | session |
| CWE-345 | Insufficient Verification | jwt |
| CWE-346 | Origin Validation Error | jwt |
| CWE-384 | Session Fixation | session |
| CWE-436 | Interpretation Conflict | bypass |
| CWE-598 | Use of GET Request Method With Sensitive Query Strings | session |
| CWE-613 | Insufficient Session Expiration | jwt, session |
| CWE-614 | Sensitive Cookie Without Secure Flag | session |
| CWE-639 | Authorization Bypass Through User-Controlled Key | idor |
| CWE-693 | Protection Mechanism Failure | session |
| CWE-770 | Allocation of Resources Without Limits | rate |
| CWE-798 | Hard-coded Credentials | bypass |
| CWE-942 | Permissive Cross-domain Policy | session |
| CWE-1004 | Sensitive Cookie Without HttpOnly | session |
| CWE-1021 | Improper Restriction of Rendered UI Layers | session |

---

## Requirements

- Python 3.10+
- `requests` (only external dependency)

---

## Author

**Adrian Martinez** — Pentester & COO at HAAK Cybersecurity Consulting

- me@adrianmartinez.lat
- [@adrian.offsec](https://instagram.com/adrian.offsec)
- [@haakconsulting](https://instagram.com/haakconsulting)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is for **authorized security testing only**. Only use against systems where you have explicit written permission. Unauthorized use may be illegal. The authors are not responsible for misuse of this tool.
