# YouTube Analytics Report Contract V1

## Purpose and boundary

This contract hardens the response boundary for the channel-scoped YouTube Analytics `reports.query` operation. It validates request syntax and the report table shape before returning data to RhemaScript. Google remains authoritative for whether a metric, dimension, filter or combination is supported by a particular report.

## Request validation

- The query is restricted to the authenticated channel selector `channel==MINE`.
- Dates must be canonical `YYYY-MM-DD` values, and the end date cannot precede the start date. The inclusive range is capped at 10,000 days to bound local calendar-coverage and comparison work.
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

## Supported response data types and row identity

The client applies an explicit supported type contract before returning or snapshotting a result table:
- Dimension columns must declare `STRING` and contain string values.
- Metric columns must declare `INTEGER`, `FLOAT`, or `CURRENCY`. Integer columns require JSON integers (booleans are rejected); float/currency columns require finite JSON numbers. Numeric strings, booleans, nulls, and non-finite numbers are rejected.
- Unknown or newly introduced provider data types fail closed until the integration contract and tests are deliberately extended. This is the integration's supported subset, not a claim that Google's published type vocabulary is exhaustive.
- Every row must have a unique complete tuple of dimension values, matching Google's reports.query contract. Multiple rows may share one dimension value (for example, the same day across countries), but not the entire dimension tuple. A dimensionless aggregate report may contain at most one row.

These checks protect the local evidence and aggregation boundary. They do not replace Google's report-specific metric/dimension compatibility rules.

## Data freshness and interpretation

The API can omit the most recent days when all requested metrics are not yet available. An omitted row is not evidence of zero activity. Consumers must retain the requested date range, retrieval timestamp and source response metadata in any later evidence snapshot, and must not impute missing dates as zero without an explicit, separately governed transformation.

## Authorization

This code path does not initiate OAuth or broaden existing grants. The repository readiness record states that the owner's completed consent is exactly `https://www.googleapis.com/auth/youtube.readonly`.

The current Google `reports.query` reference explicitly states that requests to this method now require the `youtube.readonly` scope. The same reference also lists `yt-analytics.readonly` in its general authorization-scope table and retains an example using that scope. Treat the method-specific requirement as the current minimum documented requirement; do not infer that the broader feature inventory in this repository must be granted together. The current recorded owner consent matches the method-specific requirement for channel-scoped report queries.

Source checked 13 November 2026: https://developers.google.com/youtube/analytics/reference/reports/query

No live Analytics request was made in this implementation or its synthetic tests. Before the first live query, verify that the local credential is still the same owner-authorized credential and that the intended Google account/channel remains correct. Do not request or add scopes unless a specific API operation demonstrably requires them and the owner separately approves that consent.

## Verification boundary

Tests use synthetic report objects and mocked transports. They do not prove live Google authorization, report availability, channel ownership, production readiness or the correctness of Google-side metric calculations.
