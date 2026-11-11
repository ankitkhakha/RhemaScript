# RAEI Local Evidence Ledger Prototype

Python standard library only. This prototype records learning units, assessment outcomes and a SHA-256 hash-chained event history. It does not certify competence or grant production authority.

Run from the repository root:

```sh
python -m unittest discover -s tests -v
python -m raei.ledger --ledger demo.json init
python -m raei.ledger --ledger demo.json add-unit CS-01 "Computer science foundations"
python -m raei.ledger --ledger demo.json assess CS-01 3 tests/test_ledger.py::test_verified_pass_and_prerequisite
python -m raei.ledger --ledger demo.json report
```

Only a score of at least 3 with a verified evidence reference can pass a unit. Prerequisites must already be passed. Passed units cannot be overwritten. The event chain detects edits to prior events. Evidence references are asserted by the operator and must be independently inspected. This prototype is local and deterministic. The CLI assessment command defaults to `reported_unverified`; use `--evidence-status verified` only after inspecting the referenced artefact and result. An evidence reference is an operator assertion, not automatic file inspection.


## Curriculum registry

The canonical scope is defined in `raei.curriculum`. It registers engineering units, all 66 biblical books, ten applied Bible-only ethics cases, CAP-01..15, IF-01..18, the RhemaScript specialist modules and the integrated capstone. Registry entries begin as `not_started`; registration is not study, execution, assessment or mastery.

Inspect the scope:

```sh
python -c "from raei.curriculum import registry_summary; print(registry_summary())"
python -m unittest discover -s tests -v
```

The registry is a scope index. It does not automatically mark ledger units passed or supply evidence. A lesson, practical artefact, verified assessment and correction history remain mandatory.


## RhemaScript integrity practical

`raei.integrity.validate_project_chain(project)` checks the eight source-to-final stages, all six approval gates, approval-to-artefact linkage, generation authorization evidence and prohibited publication claims. It is a validator only: it cannot approve a gate, authorize generation, generate media or publish.

Run its regression tests with:

```sh
python -m unittest tests.test_integrity -v
```

A valid report means the supplied records are structurally complete and internally linked. It does not prove that an artefact is biblically accurate, visually correct, approved by the rightful authority or safe to publish; those require inspection under the existing RhemaScript controls.


## RhemaScript project record lifecycle

`raei.project_record` creates a metadata-only project record and appends immutable-by-copy stage revision events. Stage changes invalidate the approval gate for that stage and every downstream gate, requiring fresh approval evidence. Each downstream stage must name its immediate predecessor artefact. The lifecycle helper does not approve gates, authorize or perform generation, or publish.

Example:

```python
from raei.project_record import create_project_record, revise_stage

project = create_project_record("RS-LOCAL-PRACTICAL-001")
project = revise_stage(
    project, "biblical_source", "bible-source-v1",
    "Matthew 14:22-33", "Initial contextual source record",
)
```

The example is a local learning record, not a RhemaScript production project or proof of biblical verification.


## Transactional SQLite evidence-store practical

`raei.store.EvidenceStore` is a local-only engineering practical using Python's standard-library SQLite implementation. It demonstrates atomic write transactions, foreign-key-enforced prerequisites, optimistic version checks, immutable passed units, idempotent request replay, a hash-linked audit event stream, consistent local backup/restore, and competing-writer tests.

Run:

```sh
python -m unittest tests.test_store -v
```

The test suite uses temporary local databases. It makes no network calls and does not connect to a production RhemaScript database. A passing test demonstrates behaviour of this prototype under the tested cases; it is not a production security review, backup/restore certification, or proof of all concurrency failure modes. SQLite WAL and hash-linked events are operational mechanisms, not digital signatures or proof of operator identity.


## Authorization and API-contract practical

`raei.api_contracts` adds a small deny-by-default role/action/resource policy exercise and strict request-payload validators for unit creation and assessment. Unknown fields, malformed identifiers, duplicate/self prerequisites, boolean-as-integer scores, invalid versions, and unreferenced claims of verified evidence are rejected.

Run:

```sh
python -m unittest tests.test_api_contracts -v
```

The policy consumes a preconstructed principal; it does not authenticate users, issue credentials, manage sessions, or replace a production identity provider. The example role rules are illustrative and do not grant access to RhemaScript production systems. A production implementation would need a separately authorised threat model, identity lifecycle, secure secret handling, transport protections, audit review and deployment approval.


## API security and authorization capstone practical

The expanded local lab is documented in `raei/studies/engineering/API-SECURITY-AUTHORIZATION.md`. It maps the OWASP API Security Top 10 (2023) to the RAEI syllabus and adds a multi-user record API simulation with object ownership checks, role/action authorization, field allowlists, response filtering, optimistic version checks, per-subject rate limiting and privacy-conscious audit outcomes.

Run:

```sh
python -m unittest tests.test_api_contracts tests.test_api_security_lab -v
python -m unittest discover -s tests -v
```

The lab receives a preconstructed trusted principal; it does not implement authentication, OAuth/OIDC, token validation, TLS, a network server or distributed rate limiting. The lab is not a production service or security certification. The learner must explain and test these missing controls before the competency can be assessed.


The API security lab also includes `raei.api_auth`, a strict local HMAC bearer-token verification exercise with algorithm pinning, signature verification, issuer/audience/time/role validation and negative tests. Run `python -m unittest tests.test_api_auth -v`. This is a learning boundary, not production-grade JWT/OIDC infrastructure; real issuance belongs to a trusted identity provider and production deployments require maintained libraries, key lifecycle and security review.


The API security learning suite now covers outbound destination allowlisting/SSRF policy, upstream JSON response validation and a fail-closed security configuration audit. Run `python -m unittest tests.test_outbound_security tests.test_security_config -v`. The URL validator is not a network client and does not itself mitigate DNS rebinding, redirects or connection-time peer changes; those controls remain mandatory for any real outbound HTTP integration.