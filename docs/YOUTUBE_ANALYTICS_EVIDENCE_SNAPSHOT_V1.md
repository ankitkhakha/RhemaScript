# YouTube Analytics Evidence Snapshot V1

## Purpose

A validated API response is not yet a durable evidence record. This module creates an offline, content-addressed snapshot that binds the exact channel-scoped query, retrieval timestamp, and decoded JSON response together.

## Snapshot contents

- Schema and evidence type identifiers.
- Source endpoint and operation name.
- Canonical UTC retrieval timestamp.
- Exact request parameters, including channel selector and date range.
- Exact decoded response and validated column order.
- Row count and explicit no-data flag.
- SHA-256 digest of the response.
- SHA-256 digest of the complete snapshot body.

Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects non-finite numbers. The snapshot builder and verifier do not call Google, write files, infer missing dates as zero, or produce performance recommendations.

## Use and verification

Call `build_analytics_evidence_snapshot` only after the API client has returned a response. The caller must supply the actual timezone-aware retrieval time. Persist the returned object as a separate project evidence artifact, preserving its exact bytes and digest through the existing evidence-artifact verification workflow.

Call `verify_analytics_evidence_snapshot` after loading a snapshot. It rechecks the request/response contract, timestamp, row metadata, response digest and snapshot digest. Any changed query, timestamp, response, row metadata or unsupported field invalidates verification.

## Interpretation boundary

An omitted `rows` property is represented as zero returned rows and `no_data: true`. It does not mean zero views or zero engagement. YouTube Analytics may omit recent daily rows while metrics are not yet available. Do not impute missing dates as zero without a separately governed transformation.

A valid digest proves byte consistency relative to the snapshot. It does not prove Google's authenticity beyond the authenticated API transport, channel ownership, authorization, completeness, metric correctness, or immutability against an actor able to replace both artifact and its trusted external anchor.

## Authorization and operations

No live Analytics request, OAuth action, credential read, upload, thumbnail write, publication, or deployment is performed by this module. The existing owner-authorized read-only scope is not expanded. See the YouTube Analytics report contract and Google method reference for the current scope and response requirements.
