# RAEI API Security and Authorization Practical — Completion Package

**Status:** implementation committed for CI; competency assessment remains pending.  
**Scope:** isolated in-memory lab only. No production endpoint, credential store, identity provider, network listener or real RhemaScript data is touched.

## Learning objectives

Demonstrate the difference between authentication (establishing who the caller is) and authorization (deciding what an authenticated caller may do); enforce least privilege, object ownership, property-level permissions, input validation, optimistic concurrency, rate limits and privacy-conscious audit events.

## Study syllabus

1. **API1:2023 Broken Object Level Authorization (BOLA):** every object lookup by client-supplied identifier must enforce access to that specific object.
2. **API2:2023 Broken Authentication:** identity must come from a trusted authentication boundary, not a client-supplied username or role.
3. **API3:2023 Broken Object Property Level Authorization:** response fields and writable fields must be explicitly allowlisted; reject mass assignment.
4. **API4:2023 Unrestricted Resource Consumption:** bound request rates and expensive operations; production limits must also consider distributed clients and shared infrastructure.
5. **API5:2023 Broken Function Level Authorization:** administrative operations require explicit privilege checks on every route/action.
6. **API6:2023 Sensitive Business Flows:** identify abuse-prone workflows and apply controls proportionate to risk.
7. **API7:2023 SSRF:** do not fetch arbitrary client-supplied URLs; use strict destination policy and network egress controls.
8. **API8:2023 Security Misconfiguration:** fail closed; configure TLS, CORS, headers, secrets and error handling safely.
9. **API9:2023 Improper Inventory Management:** maintain endpoint/version inventory and retire obsolete interfaces.
10. **API10:2023 Unsafe Consumption of APIs:** treat upstream responses as untrusted; validate schemas, destinations, timeouts and error behaviour.

Primary reference: OWASP API Security Top 10 (2023), linked from the project README. The list is an awareness baseline, not a complete security standard.

## Lab files

- `raei/api_contracts.py`: deny-by-default role/action/resource policy and request schema validation.
- `raei/api_security_lab.py`: multi-user record API simulation with object ownership checks, function-level checks, field allowlists, response-field filtering, optimistic version checks, per-subject rate limiting and audit outcomes.
- `tests/test_api_contracts.py`: policy and schema negative tests.
- `tests/test_api_security_lab.py`: BOLA, mass assignment, privilege boundary, stale-write, response filtering, anonymous denial, audit privacy and rate-limit tests.

## Run

```sh
python -m unittest tests.test_api_contracts tests.test_api_security_lab -v
python -m unittest discover -s tests -v
```

## Threat-to-test map

| Threat | Control demonstrated | Regression test |
|---|---|---|
| BOLA | ownership check per record | other contributor cannot read/update foreign record |
| Broken function authorization | explicit action/resource rules | reader cannot update; non-admin cannot delete |
| Property authorization / mass assignment | input and output allowlists | owner/classification/version fields rejected |
| Unrestricted resource use | per-subject rolling window | request denied at configured limit |
| Stale/concurrent modification | expected version | stale update rejected |
| Sensitive audit leakage | audit stores actor/action/id/outcome only | audit event contains no record body |
| Anonymous access | missing principal denied | anonymous read rejected |

## Expected design decisions

- Never accept role, owner identity or authentication status from an untrusted request body.
- Obtain the principal only from a verified authentication middleware boundary.
- Check object access after resolving the object and before returning or modifying it.
- Apply authorization to every action, not only the UI or route navigation.
- Use allowlisted fields for reads and writes; do not serialize database objects wholesale.
- Treat errors and audit logs as potentially sensitive; avoid logging tokens, passwords, private bodies or secrets.
- Use TLS, secure token validation, expiry/revocation, key rotation, CSRF protections where relevant, safe CORS, request-size limits and robust abuse controls in a real deployment. These are not implemented by this local lab.
- Do not treat a role name stored in a mutable client token as proof of privilege. Verify issuer, audience, signature, expiry and relevant claims at the authentication boundary.

## Deliberate limitations

This lab is in-memory and single-process. Its rate limiter is not distributed, its audit list is not durable, and the supplied Principal is trusted input. There is no HTTP framework, TLS, OAuth/OIDC implementation, token issuance, password handling, session management, database persistence or deployment. No production readiness claim follows from its tests.

## Assessment

A learner must explain authentication versus authorization, identify the trust boundary, demonstrate BOLA and mass-assignment failures against an intentionally unsafe example, repair them, add a regression test for each, explain the OWASP API risks, and document remaining deployment risks. Score each dimension 0–4: conceptual accuracy, threat identification, implementation, negative testing, evidence/limitations. Pass requires at least 3 in every dimension and no critical failure.

**Current competency result:** not assessed. Code and tests are practice artefacts, not a passed assessment.


## Authentication boundary practical (additional)

`raei.api_auth` adds a strict, standard-library HMAC-SHA256 bearer-token verification exercise. It checks the signature before trusting claims; pins the accepted algorithm to HS256; rejects malformed, oversized and duplicate-key JSON; validates issuer, audience, subject, expiry, not-before and an allowlist of roles; and uses constant-time signature comparison.

Additional tests are in `tests/test_api_auth.py`.

Run:

```sh
python -m unittest tests.test_api_auth -v
python -m unittest tests.test_api_contracts tests.test_api_security_lab tests.test_api_auth -v
```

The token issuer helper exists only to create local test tokens. Real token issuance and identity lifecycle belong to a trusted identity provider. The HMAC secret is injected and must be managed outside source control. This deliberately small implementation is for learning and must not replace a maintained, security-reviewed OIDC/JWT library in production. It does not implement key rotation, asymmetric signatures, revocation, refresh tokens, discovery, TLS, or secure secret storage. Do not put a production secret in tests or repository files.


## SSRF, upstream response and security configuration practicals

- `raei.outbound_security.validate_outbound_url` enforces HTTPS, exact hostname allowlisting, port 443 only, no URL credentials, no fragments, and rejects IP-literal and local hostnames.
- `validate_upstream_json` requires JSON content type, caps body size, rejects invalid UTF-8/JSON, duplicate keys and non-object roots.
- `raei.security_config.audit_security_config` checks explicit safe defaults for debug, TLS, cookie flags, SameSite, CSRF, CORS, trusted proxy hops, session-secret length and baseline response security headers.
- Tests: `tests/test_outbound_security.py` and `tests/test_security_config.py`.

Run:

```sh
python -m unittest tests.test_outbound_security tests.test_security_config -v
python -m unittest discover -s tests -v
```

**Important boundary:** URL validation is only a pre-request policy check. It does not resolve DNS, pin the resolved address, verify the connected peer, or validate redirect targets. A real HTTP client must disable redirects or revalidate every redirect and enforce public-address checks at connection time to mitigate DNS rebinding and resolution races. The exercise performs no network requests. The configuration audit is a teaching checklist, not a framework-specific deployment scanner.
