# RhemaScript NEW SYSTEM

Greenfield, Scripture-centred content intelligence and production operating system.

## RAEI — Autonomous Engineering Intelligence

RAEI is the engineering specialist capability for understanding, designing, building, securing, testing and maintaining RhemaScript. It is governed by a versioned engineering constitution, progressive education framework, competency evaluation standard and activation guide.

- [RAEI Engineering Constitution V1.0](docs/RAEI_ENGINEERING_CONSTITUTION_V1.md)
- [RAEI Education Framework V1.0](docs/RAEI_EDUCATION_FRAMEWORK_V1.md)
- [RAEI Competency and Evaluation Standard V1.0](docs/RAEI_COMPETENCY_AND_EVALUATION_V1.md)
- [RAEI Activation and Operating Guide V1.0](docs/RAEI_ACTIVATION_AND_GOVERNANCE_V1.md)

Conversational activation: `ACTIVATE RAEI`. Activation does not grant permissions or start a background process. Education is competency-based; documentation does not imply model-weight retraining or achieved competence.

## Creative filmmaking intelligence

See [Creative Filmmaking Intelligence V1.0](docs/CREATIVE_FILMMAKING_INTELLIGENCE_V1.md) for the integrated biblical, human-experience, creative-story, filmmaking, AI-tool, production, and quality-learning operating model, including the Gemini/Google Flow capability snapshot verified 2026-11-11.

## YouTube integration

The zero-cost official API client is in `rhemascript.integrations.youtube`. See [YouTube Integration — Zero Cost V1.0](docs/YOUTUBE_INTEGRATION_ZERO_COST_V1.md).

The client supports authenticated channel retrieval, resumable video upload, metadata, scheduled publication, custom thumbnails, upload verification and YouTube Analytics queries. It uses Python's standard library and has no added package dependencies. Credentials are injected from local environment variables; no secrets are stored in source control. Publishing operations fail closed without explicit publishing authority and uploaded videos default to private.

**Activation is not yet complete:** the channel owner must configure an existing Google Cloud project, enable the official APIs, complete OAuth consent and provide a refresh token locally. No real channel connection, upload, public release or analytics retrieval has been performed by CI. The client code and mockable tests are not proof of live provider access or production readiness.

## Local CI

Run:

```bash
python ci/run_ci.py
```

The suite validates shared record envelopes, authority separation, CTMNDS disclosure controls, six project approval gates, all 15 capability contract entry points, all 18 local interface adapters, RAEI governance and education documents, a synthetic end-to-end contract flow, and YouTube integration guardrails.

## Scope and limitations

Capability execution provides evidence-gated contract infrastructure. It does not replace specialist biblical interpretation, legal/rights review, security assurance, visual analysis, or human editorial decisions. The original IF-01..IF-18 adapters remain local-only; the YouTube client is a separate explicit provider integration and makes no request until invoked.

No media generation, spending, deployment, or live YouTube publishing is performed automatically. External writes require explicit publishing authorisation and real API credentials.
