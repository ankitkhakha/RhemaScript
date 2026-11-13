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

V1 uses a metric-specific aggregation allowlist. Additive metrics such as views, estimated watch minutes and subscribers gained are summed using decimal arithmetic. `averageViewDuration` is not summed: it is calculated as total estimated watch minutes multiplied by 60, divided by total views, and is labelled as a weighted average in seconds. This requires views and estimated watch minutes in the same query. Other metrics without an explicit V1 aggregation contract are rejected rather than silently summed. Boolean, non-finite, malformed, or fractional values in an integer metric are rejected.

The result reports current and previous metric values, their aggregation method, absolute difference, and percentage difference when both periods contain rows and the previous value is nonzero. A zero baseline receives `ZERO_BASELINE` and no percentage. If either period has no returned rows, the comparison reports `INSUFFICIENT_DATA` and does not substitute zero.

The comparison also records period lengths and returned-row counts. It does not claim that every expected day or dimension bucket was returned. In particular, an absent recent daily row is not evidence of zero activity.

## Interpretation boundaries

- These are observed totals over rows returned by the API, not a causal explanation.
- Equal date-range length does not guarantee equal data completeness.
- Totals for metrics such as views and estimated watch minutes are not interchangeable with averages or rates.
- This V1 does not compute retention cohorts, audience segmentation, statistical significance, forecasts, or recommendations.
- A content-addressed digest establishes integrity relative to the captured object, not independent provider authenticity or immutable external custody.

## Next governed stages

1. Add completeness diagnostics for daily dimensions and known reporting delays.
2. Add explicitly defined rate and weighted-average calculations with metric-specific contracts.
3. Store findings separately from raw snapshots and comparisons.
4. Generate recommendations only as labelled hypotheses, then record implementation decisions and measured outcomes independently.

No live Analytics data is included in this change. Synthetic tests verify arithmetic and failure handling only.
