# YouTube Analytics Report Contract V1

## Purpose and boundary

This contract hardens the response boundary for the channel-scoped YouTube Analytics `reports.query` operation. It validates request syntax and the report table shape before returning data to RhemaScript. Google remains authoritative for whether a metric, dimension, filter or combination is supported by a particular report.

## Request validation

- The query is restricted to the authenticated channel selector `channel==MINE`.
- Dates must be canonical `YYYY-MM-DD` values, and the end date cannot precede the start date.
- Metrics must contain at least one unique identifier. Dimensions may be omitted; when supplied, identifiers must be unique.
- Identifiers are syntax-checked and cannot contain query delimiters, whitespace, or injected parameters.
- Filters are limited to semicolon-separated `dimension==value` clauses. Empty clauses, malformed operators, control characters and oversized values are rejected.
- This syntax validation does not claim that a metric/dimension/filter combination is supported. The Analytics API's report-specific contract remains authoritative.

## Response validation

- The response kind must be `youtubeAnalytics#resultTable`.
- Column headers must match the requested dimensions followed by requested metrics, in the exact requested order.
- Every header must declare a non-empty data type and the expected `DIMENSION` or `METRIC` column type.
- If `rows` is omitted, it is treated as an empty result set. If present, it must be a list.
- Every row must be a list with exactly one scalar value per header. Nested objects, nested lists and malformed row widths are rejected.

## Data freshness and interpretation

The API can omit the most recent days when all requested metrics are not yet available. An omitted row is not evidence of zero activity. Consumers must retain the requested date range, retrieval timestamp and source response metadata in any later evidence snapshot, and must not impute missing dates as zero without an explicit, separately governed transformation.

## Authorization

This code path does not initiate OAuth or broaden existing grants. The owner's currently documented consent is `youtube.readonly` only. Google documentation currently contains both a method-specific statement requiring `youtube.readonly` and a general scope table listing `yt-analytics.readonly`; verify the live consent and method requirements with the owner before attempting any live Analytics request. No live request is part of this implementation or its synthetic tests.

## Verification boundary

Tests use synthetic report objects and mocked transports. They do not prove live Google authorization, report availability, channel ownership, production readiness or the correctness of Google-side metric calculations.
