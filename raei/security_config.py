"""Production security configuration checks; returns actionable failures."""
from __future__ import annotations


def audit_security_config(config: dict) -> list[str]:
    """Return stable, fail-closed findings for a minimal web-service config."""
    if not isinstance(config, dict):
        return ["configuration must be an object"]
    findings = []

    if config.get("debug") is not False:
        findings.append("debug must be explicitly false")
    if config.get("tls_required") is not True:
        findings.append("TLS must be explicitly required")
    if config.get("secure_cookies") is not True:
        findings.append("secure cookies must be explicitly enabled")
    if config.get("http_only_cookies") is not True:
        findings.append("HttpOnly cookies must be explicitly enabled")
    if config.get("same_site") not in {"Lax", "Strict"}:
        findings.append("SameSite must be Lax or Strict")
    if config.get("csrf_protection") is not True:
        findings.append("CSRF protection must be explicitly enabled")
    origins = config.get("cors_allowed_origins")
    if not isinstance(origins, list) or not origins:
        findings.append("CORS origins must be a non-empty explicit list")
    elif "*" in origins:
        findings.append("wildcard CORS origin is forbidden")
    if config.get("trusted_proxy_hops") is None:
        findings.append("trusted proxy hops must be explicitly configured")
    elif (not isinstance(config["trusted_proxy_hops"], int)
          or isinstance(config["trusted_proxy_hops"], bool)
          or config["trusted_proxy_hops"] < 0):
        findings.append("trusted proxy hops must be a non-negative integer")
    secret = config.get("session_secret")
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        findings.append("session secret must contain at least 32 UTF-8 bytes")
    headers = config.get("security_headers")
    required = {"content-security-policy", "x-content-type-options",
                "referrer-policy", "strict-transport-security"}
    if not isinstance(headers, dict):
        findings.append("security headers must be explicitly configured")
    else:
        missing = sorted(required - {str(k).lower() for k in headers})
        if missing:
            findings.append("missing security headers: " + ", ".join(missing))
    return findings
