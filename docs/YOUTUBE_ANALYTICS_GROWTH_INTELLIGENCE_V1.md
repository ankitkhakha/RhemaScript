# YouTube Analytics Growth Intelligence — Period Comparison V1

## Purpose

This stage creates deterministic descriptive comparisons from two already-built, hash-verified Analytics snapshots. It is deliberately offline and does not make provider requests, retrieve credentials, publish content, or generate recommendations.

## Input requirements

Both inputs must pass the V1 snapshot verifier. They must have:
- The same channel selector, metrics, dimensions, and filters.
- Equal inclusive date-range lengths.
- Non-overlapping chronological periods, with the current period strictly after the previous period.

The comparison binds both source snapshot digests. A changed or unverified input is rejected.

## Calculation contract

V1 uses a metric-specific aggregation allowlist. Additive metrics such as views, estimated watch minutes and subscribers gained are summed using decimal arithmetic. `averageViewDuration` is not summed: it is calculated as total estimated watch minutes multiplied by 60, divided by total views, and is labelled as a weighted average in seconds. This requires views and estimated watch minutes in the same query. Other metrics without an explicit V1 aggregation contract are rejected rather than silently summed. Boolean, negative, non-finite, malformed, or fractional values in an integer metric are rejected.

The result reports current and previous metric values, their aggregation method, absolute difference, and percentage difference when both periods contain rows and the previous value is nonzero. A zero baseline receives `ZERO_BASELINE` and no percentage. If either period has no returned rows, the comparison reports `INSUFFICIENT_DATA` and does not substitute zero.

The comparison also records period lengths and returned-row counts. It does not claim that every expected day or dimension bucket was returned. In particular, an absent recent daily row is not evidence of zero activity.

## Daily coverage diagnostic

For reports that include the `day` dimension, the coverage diagnostic lists expected dates, distinct dates represented by returned rows, and missing dates. For reports with additional dimensions (for example country), it counts distinct day labels rather than treating each dimension row as a separate day. Reports without the `day` dimension receive `NOT_APPLICABLE`; the comparison remains valid and does not fabricate a calendar-coverage result.

The diagnostic is bound to the exact source snapshot and can be recomputed for verification. Missing dates remain unknown/not returned; the diagnostic does not infer reporting delay, zero activity, or the reason for missing data.

## Interpretation boundaries

- These are observed totals over rows returned by the API, not a causal explanation.
- Equal date-range length does not guarantee equal data completeness.
- Totals for metrics such as views and estimated watch minutes are not interchangeable with averages or rates.
- This V1 does not compute retention cohorts, audience segmentation, statistical significance, forecasts, or recommendations.
- A content-addressed digest establishes integrity relative to the captured object, not independent provider authenticity or immutable external custody.

## Next governed stages

1. Add provider-grounded reporting-delay rules only after confirming the official API contract and observed account behaviour.
2. Add explicitly defined rate and weighted-average calculations with metric-specific contracts.
3. Store findings separately from raw snapshots and comparisons.
4. Generate recommendations only as labelled hypotheses, then record implementation decisions and measured outcomes independently.

No live Analytics data is included in this change. Synthetic tests verify arithmetic and failure handling only.


## Offline artifact persistence

`persist_analytics_evidence_artifact` accepts only a verified V1 snapshot or a digest-verified period comparison. It writes a canonical JSON envelope beneath an existing evidence-root directory, refuses to overwrite an existing path, rejects symlinked path components, uses owner-only file permissions, flushes the file and parent directory, and re-verifies the resulting file bytes.

The returned project evidence-pack artifact record is always `DRAFT`. It carries the file-byte `sha256` separately from the internal `snapshot_sha256` or `comparison_sha256`. Comparison records also carry the exact current and previous snapshot artifact IDs. The caller must add these records to the project's evidence pack and link the two snapshot artifacts to the derived comparison. Byte verification proves local content identity only; it does not grant approval, establish provider authenticity, or create immutable external custody.

Parent directories must already exist. The helper does not create directories, follow symlinks, replace existing evidence, contact Google, or access credentials.
