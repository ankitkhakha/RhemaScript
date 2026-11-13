# Trusted External Approval Issuer and Human Identity Contract V1.0

Status: architecture contract for WRK-060; not a deployed issuer and not a production identity integration.

## 1. Objective

Establish an independently authenticated human identity and role boundary for every governed approval. A caller-supplied actor name, email address, role, group, session identifier or boolean is never proof of identity or authority.

The external issuer is the sole authority that authenticates the human, resolves the human's current role, evaluates the applicable approval policy and signs an approval credential. RhemaScript remains a relying party: it receives signed credentials, verifies them against pinned public keys and consumes them atomically. RhemaScript must not collect passwords, identity-provider access tokens, private signing keys or session cookies.

## 2. Trust boundaries

1. Human operator — authenticates directly with the organization's approved identity provider.
2. Identity provider — authenticates the subject and returns a signed, audience-bound authentication result.
3. Trusted approval issuer — validates the identity-provider result, resolves roles from an authoritative directory, evaluates action/project policy and signs a short-lived approval credential.
4. RhemaScript verifier — verifies signature, issuer, key status, credential schema, identity assurance, action, project/version/request, exact artifact binding, time limits and replay/revocation state.
5. Provider gateway — independently enforces two distinct verified human approvals and exact artifact binding before any provider write.

The application caller is not an identity authority. It may request an approval for a defined scope, but it cannot nominate the approving actor or alter identity claims.

## 3. Required authentication procedure

The production issuer must:

- use an approved organizational identity provider and an authorization-code flow with PKCE and state/nonce validation where applicable;
- validate token signature, exact issuer, audience, expiry, not-before, nonce, authorized client and authentication time;
- reject unsigned, weakly signed, wrong-audience, replayed, expired or ambiguous identity results;
- require phishing-resistant MFA for publication-sensitive actions where the organization supports it; otherwise require the formally approved MFA assurance level and record the exception policy;
- perform fresh authentication or step-up authentication for high-risk approval actions;
- resolve current role and employment/contractor status from an authoritative directory at approval time, not from caller input or stale client-side claims;
- evaluate project-specific assignment and separation-of-duties policy;
- bind the approval to the identity-provider subject, authentication event, issuer session, exact requested action and evidence scope;
- issue no approval if identity, role, session, policy or directory status cannot be verified.

A login session proves authentication, not authorization. Role membership must be separately evaluated.

## 4. Signed credential identity claims — proposed V3

The next credential revision must preserve all V2 fields and add signed identity-assurance claims:

- `subject_id`: stable, issuer-scoped pseudonymous subject identifier; avoid email addresses and other unnecessary personal data;
- `actor_role`: one canonical role identifier resolved by the issuer;
- `authn_context`: controlled assurance value, including the MFA/step-up level actually achieved;
- `authenticated_at`: timezone-aware time of the authentication event;
- `identity_session_id`: opaque issuer session/event reference, not a bearer session token;
- `identity_policy_version`: immutable identifier of the role/action policy applied;
- `identity_provider_id`: allowlisted identity-provider identifier, not an arbitrary URL.

All claims must be included in the Ed25519 signature. Missing or unknown identity claims, unrecognized roles, unsupported assurance values, stale authentication, or a policy version not trusted by the relying party must fail closed for governed actions.

The legacy V1/V2 formats must not be silently interpreted as identity-assured. A migration plan must state which low-risk workflows may continue using them. High-risk final acceptance and publication must require the identity-assured format once that enforcement is implemented.

## 5. Role and separation-of-duties policy

The issuer must maintain a versioned, owner-approved action-to-role matrix. Example role categories (final names and assignments require owner approval):

- `CONTENT_REVIEWER`: review content/evidence; cannot publish;
- `FINAL_ACCEPTOR`: accept an exact final artifact; cannot be the publisher for the same request;
- `PUBLISH_AUTHORIZER`: authorize publication of an accepted exact artifact;
- `SECURITY_ADMIN`: manage issuer policy and keys; does not automatically gain content-approval authority;
- `AUDITOR`: read audit evidence; cannot issue approvals.

The issuer must enforce:
- one authenticated human per approval event;
- different subject IDs for FINAL_ACCEPTANCE and PUBLISH;
- no self-approval where the actor created, materially edited or generated the artifact, unless a separately approved exception explicitly permits it;
- least privilege and project-specific assignment;
- no privilege escalation from client-supplied claims;
- current role membership at issuance time;
- policy version and decision outcome recorded in the issuer's immutable audit stream.

The relying party must independently require distinct actor/subject identities in the signed approvals. Distinct display names or accounts are not sufficient if they resolve to the same underlying subject.

## 6. Signing key and issuer operations

- Keep Ed25519 private signing keys in an HSM or managed KMS with narrowly scoped signing permission. No private key may enter this repository, CI, application configuration, local database or archive.
- Separate production, staging and test issuers and keys. Test keys must never be trusted in production.
- Publish a signed or otherwise integrity-protected key registry containing issuer ID, key ID, public key, environment, validity interval, allowed credential schemas and status.
- Support overlapping key rotation: publish the new public key before use, begin signing with it, retain the old public key for historical verification, then revoke it according to documented incident/retention policy.
- Maintain an emergency key-revocation path and define how already-issued but not-yet-consumed credentials are invalidated.
- Use short credential lifetimes, unique approval IDs and nonces, and atomic replay consumption.
- Log issuance, denial, role resolution, step-up result, key ID, policy version, subject reference, action and scope. Never log passwords, bearer tokens, private keys or unnecessary personal data.

## 7. Failure and recovery behavior

The issuer must fail closed when the identity provider, directory, policy service, signing key, key registry or audit sink is unavailable or returns an ambiguous result. There is no offline bypass, manually supplied actor ID, boolean override or fallback signing key.

Define operational runbooks for:
- identity-provider outage;
- directory/role-service outage;
- signing-key compromise or suspected misuse;
- public-key rotation and emergency revocation;
- issuer database/audit-stream recovery;
- clock drift and timestamp validation;
- subject disablement, role removal and termination;
- reconciliation of approvals issued immediately before revocation.

A previously issued credential remains cryptographically verifiable after expiry, but must not be accepted for a new action after expiry. Historical audit must distinguish signature validity from current authorization status.

## 8. Privacy and audit data minimization

Use issuer-scoped pseudonymous subject IDs in approval credentials and RhemaScript records. Keep any mapping to legal identity inside the organization's identity/issuer audit boundary with restricted access and retention. RhemaScript should persist only the claims necessary to prove the signed decision and its scope. Never copy identity-provider tokens or authentication secrets into the Evidence Pack.

## 9. Required conformance tests before production

The issuer and relying-party integration must prove rejection of:

- caller-supplied or altered actor/role claims;
- invalid identity-provider signature, issuer, audience, nonce, state or PKCE result;
- stale authentication or insufficient MFA assurance;
- inactive user, removed role, wrong project assignment or unapproved role;
- role/action mismatch and policy-version mismatch;
- same underlying subject approving both final acceptance and publication;
- self-approval and unauthorized policy exceptions;
- revoked, unknown, expired or environment-mismatched signing keys;
- replayed approval IDs/nonces and altered artifact digest/version/size;
- identity provider, directory, policy, key registry or audit sink outage;
- clock skew outside the configured bound;
- attempts to use legacy V1/V2 credentials for high-risk actions after the migration cutoff.

Tests must include issuer contract tests, verifier tests, gateway tests, key-rotation/revocation tests, outage/recovery drills and independent adversarial review.

## 10. Implementation sequence and status

1. Approve the identity provider, role matrix, assurance levels, self-approval rules and accountable issuer owner.
2. Specify and implement credential V3 identity claims and verifier enforcement.
3. Extend durable approval persistence and checkpoint archives to preserve the V3 claims.
4. Implement the external issuer service and HSM/KMS signing integration outside RhemaScript's application process.
5. Integrate the issuer client without exposing identity tokens or private keys to RhemaScript.
6. Run conformance and independent security tests.
7. Obtain explicit owner authorization before any production identity-provider or provider integration.

Current state: the existing code has a protocol boundary that deliberately accepts no caller-supplied actor ID and verifies externally signed credentials. However, the current V1/V2 credential schemas do not carry signed role/MFA/session assurance claims, and no production issuer or human-authentication service is deployed. Therefore the authenticated human identity and role boundary is NOT COMPLETE. This document is a proposed contract, not evidence of production authentication.

No Google/YouTube authorization, live identity-provider connection, deployment or provider write is required or performed by this design work.
