# Production Human Identity Approval Issuer — Reference Architecture V1.0

Status: vendor-neutral design only. This document does not select an identity provider, authorize a production deployment, or establish that any human has been authenticated.

## 1. Purpose and boundary

The issuer is a separately operated trust service that authenticates a human, resolves their current authorization from an authoritative directory, applies approval policy, and signs a short-lived RhemaScript ApprovalCredential V3. RhemaScript is a relying party only. It must never receive identity-provider bearer tokens, passwords, cookies, private signing keys, or raw authentication assertions.

The architecture is designed for a later owner-approved implementation. No provider, cloud, directory, HSM/KMS, hosting platform, or production role matrix is selected here.

## 2. Logical components

1. **Approval request client** — presents a specific project, version, request, action, and exact artifact tuple. It cannot nominate an approver or assert a role.
2. **Issuer web front end** — displays the exact approval scope and directs the human to authenticate with the configured identity provider. It does not collect passwords.
3. **Identity provider (IdP)** — authenticates the human and returns a signed result to the issuer through a supported standard flow.
4. **Identity validation adapter** — validates signature, issuer, audience, authorized client, nonce, state, PKCE, expiry, not-before, authentication time, and approved authentication-context evidence.
5. **Authoritative directory adapter** — resolves immutable subject mapping, active status, current roles, project assignments and relevant employment/contractor status at issuance time. Client-supplied role claims are never authoritative.
6. **Policy decision point (PDP)** — evaluates action-to-role mapping, project assignment, separation of duties, self-approval restrictions, authentication assurance, freshness and policy version.
7. **Credential issuer** — creates a strict V3 payload from validated server-side facts and signs its canonical representation.
8. **Signing service** — holds private keys in an owner-approved HSM/KMS or equivalent protected signing boundary. Private key bytes never enter application memory, repository, CI or local database.
9. **Key registry** — publishes trusted issuer/key metadata, environment, credential-schema scope, validity and revocation status through an integrity-protected distribution process.
10. **Replay and issuance store** — enforces unique approval IDs/nonces and records idempotency, issuance decisions and policy versions.
11. **Independent audit sink** — records successful and denied decisions, identity validation outcome, directory resolution, policy decision, key ID and scope without recording secrets or unnecessary personal data.

## 3. Trust and data-flow sequence

1. RhemaScript creates an approval request containing project ID/version, request ID, action, and exact final-artifact ID/version/SHA-256/byte length. The request is immutable for the approval transaction.
2. The issuer validates the request's source and scope using an authenticated service-to-service channel and its own allowlist. It does not accept an actor ID, role, subject ID, MFA result, or policy version from the requesting client.
3. The issuer creates a one-time authorization transaction with cryptographically random state, nonce, PKCE verifier/challenge, expiry and a server-side request binding.
4. The human is redirected to the owner-approved IdP. Authentication and any step-up challenge occur directly between the human and IdP.
5. The issuer validates the returned authentication result: cryptographic signature, exact issuer/audience/client, state, nonce, PKCE, time claims, replay status, and authentication-context evidence. An ID token alone is not treated as proof of adequate MFA unless documented assurance semantics support that interpretation.
6. The issuer resolves the subject against the authoritative directory. It checks account status, current role membership, project assignment, and policy-relevant restrictions at approval time.
7. The PDP evaluates the requested action, policy version, approved authentication context and age, project assignment, self-approval and separation-of-duties constraints. Any missing, stale, conflicting or unavailable input produces a denial.
8. The issuer displays the canonical action and exact artifact digest to the human and records explicit confirmation bound to the same server-side authorization transaction.
9. The issuer creates V3 claims: issuer-scoped pseudonymous subject ID, canonical role, authentication context/time, opaque session reference, immutable policy version and IdP identifier. It binds the request and exact artifact tuple.
10. The signing service signs the canonical V3 payload. The issuer persists the issuance decision and signed credential fingerprint in its audit store before returning the credential.
11. RhemaScript independently verifies the signature, trusted issuer/key, V3 schema, configured policy, action, project/version/request, exact artifact tuple, freshness and replay/revocation state. The provider gateway independently checks final-acceptance/publish separation and rechecks authentication freshness immediately before a write.
12. Issuer and relying-party audit records are correlated by opaque request/approval IDs. No IdP access token or bearer session token is passed to RhemaScript.

## 4. Required issuer invariants

- Signed V3 claims are emitted only from validated server-side identity, directory and policy facts.
- Client-provided role, subject, IdP, MFA, session or policy claims are ignored and never copied into a credential.
- Subject IDs are stable and issuer-scoped; legal-identity mapping remains inside the issuer/organization boundary.
- The approval UI presents the same exact artifact digest that is signed and later verified.
- Approval IDs, nonces, state and authorization transactions are unique, short-lived and single-use.
- Final-acceptance and publish approvals resolve to different underlying human subjects and different authorization sessions.
- Role and project assignment are resolved at approval time; later role removal/revocation is handled by an explicit policy for outstanding credentials.
- Unknown, stale, ambiguous, revoked, unavailable or untrusted dependencies fail closed.
- The issuer cannot approve its own policy changes or signing-key changes as a substitute for independent governance.
- Production and non-production issuers, keys, registries and audit streams are isolated.

## 5. Protocol and credential implementation notes

- Prefer a standards-based authorization-code flow with PKCE; use exact redirect URI allowlists and server-side state/nonce storage.
- Validate algorithms against an explicit allowlist; reject algorithm confusion, unsigned tokens, unexpected key sources, untrusted token-supplied key discovery and weak signing algorithms.
- Validate exact issuer and audience, authorized party/client, nonce, state, PKCE, expiry, not-before, issuance time where applicable, and authentication time. Define clock tolerance centrally.
- Treat acr/amr or provider-specific MFA fields as provider-specific evidence, not universally equivalent labels. Document and test the mapping to RhemaScript controlled authn_context values.
- Do not put bearer tokens, email addresses, display names, raw IdP tokens, passwords, secrets or private keys in V3 claims.
- Signed identity_policy_version must map to an immutable, owner-approved relying-party policy. Unknown or retired versions fail closed for new high-risk actions.
- Key discovery must be pinned or integrity-protected; signing-key rotation, overlap, revocation and historical verification must be explicit.

## 6. Threat-to-control matrix

| Threat | Required control | Evidence before production |
|---|---|---|
| Caller forges actor/role | Server-side subject and directory resolution; no caller-supplied identity claims | Negative issuer API tests and independent review |
| Token substitution/replay | Signature, issuer/audience, nonce/state/PKCE, single-use transaction | Protocol conformance and replay tests |
| MFA downgrade | Explicit assurance mapping and fresh step-up policy | Provider-specific assurance evidence and downgrade tests |
| Stale or removed role | Directory lookup at issuance; short-lived credentials; revocation/role-removal policy | Directory integration tests and revocation drill |
| Same person approves twice | Stable issuer-scoped subject IDs and distinct approval sessions | Cross-account identity mapping tests |
| Artifact substitution | Signed exact artifact ID/version/digest/size | Tamper and artifact replay tests |
| Key compromise | HSM/KMS access control, rotation, revocation and incident runbook | Key lifecycle review and recovery drill |
| Policy drift | Immutable policy versions and fail-closed allowlist | Policy migration and rollback tests |
| Audit omission | Independent durable audit sink; fail closed on required audit failure | Outage, integrity and reconciliation tests |
| IdP/directory outage | No fallback or manual identity bypass | Fault injection and outage drill |

## 7. Interfaces to implement after owner approval

Keep adapters narrow and vendor-neutral:

- IdentityProtocolAdapter: starts authorization, validates callback and returns a normalized authentication event.
- SubjectDirectoryAdapter: resolves immutable subject, active status, roles and project assignments.
- ApprovalPolicyEngine: evaluates action, project, subject, role, assurance, freshness, self-approval and separation-of-duties rules.
- SigningKeyProvider: signs only approved canonical V3 payloads and exposes public-key metadata; never exports private key material.
- IssuanceLedger: enforces idempotency, one-time transactions, approval ID/nonce uniqueness and audit linkage.
- IssuerAuditSink: stores issuance/denial evidence with retention and integrity guarantees.

These are interface boundaries, not implemented production services. Do not add a concrete provider SDK, credentials, endpoint, deployment manifest or real identity policy until the owner has approved provider, directory, roles, assurance semantics, data residency, operational owner and key custody.

## 8. Owner decisions required before implementation

1. Identity provider and supported authentication protocol.
2. Authoritative directory and source of truth for active status, roles and project assignments.
3. Action-to-role matrix and least-privilege assignments.
4. Required MFA/step-up assurance for final acceptance and publication, including accepted provider evidence semantics.
5. Self-approval and creator/editor conflict rules, including any exception process.
6. Issuer service owner, operators, audit owners and incident responders.
7. HSM/KMS/key custody, environment separation, rotation and revocation ownership.
8. Privacy, retention, data residency and subject-ID mapping requirements.
9. Recovery objectives and behavior during IdP, directory, key or audit outages.

Until these are approved, keep the architecture vendor-neutral and use synthetic test fixtures only.

## 9. Delivery and stoppage gates

- **Gate A — Architecture review:** confirm trust boundaries, interfaces and threat model. No provider selected.
- **Gate B — Owner policy approval:** obtain explicit decisions in Section 8. Stop if any are missing.
- **Gate C — Synthetic issuer prototype:** implement adapters against deterministic fakes only; no production credentials or external connections.
- **Gate D — Independent security review:** review protocol validation, subject mapping, key custody, audit and failure behavior.
- **Gate E — Staging integration:** requires separate explicit approval and staging-only credentials.
- **Gate F — Production readiness:** requires signed owner authorization, operational runbooks, monitoring, key lifecycle evidence and rollback/recovery proof.
- **Gate G — Production enablement:** requires a separate explicit authorization. This document does not grant it.

## 10. Current status

V3 credential verification, policy checks, durable identity-claim persistence, signature re-verification, provider-gateway subject separation, session separation and provider-write authentication-freshness rechecks are candidate code on PR #62. These do not authenticate a real human. The production issuer, IdP adapter, authoritative directory adapter, production policy and HSM/KMS integration are not implemented or connected. Synthetic CI success is necessary but not production certification.

No identity provider, directory, cloud, signing service, external endpoint or production role matrix has been selected. No external identity connection, deployment, merge or live provider write is authorized by this architecture work.
