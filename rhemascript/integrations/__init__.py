"""RhemaScript external provider integrations."""
from .audit import AuditSinkError, JsonlAuditSink
from .youtube import YouTubeClient, YouTubeConfig, YouTubeIntegrationError
from .youtube_analytics_coverage import (
    YouTubeAnalyticsCoverageError,
    diagnose_daily_coverage,
    verify_daily_coverage_diagnostic,
)
from .youtube_analytics_artifact_store import (
    YouTubeAnalyticsArtifactStoreError,
    persist_analytics_evidence_artifact,
)
from .youtube_analytics_insights import (
    YouTubeAnalyticsInsightError,
    compare_analytics_periods,
    verify_analytics_period_comparison,
)
from .youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError,
    build_analytics_evidence_snapshot,
    verify_analytics_evidence_snapshot,
)


__all__ = ["AuditSinkError", "JsonlAuditSink", "YouTubeClient", "YouTubeConfig", "YouTubeIntegrationError", "YouTubeAnalyticsEvidenceError", "build_analytics_evidence_snapshot", "verify_analytics_evidence_snapshot", "YouTubeAnalyticsInsightError", "compare_analytics_periods", "verify_analytics_period_comparison", "YouTubeAnalyticsArtifactStoreError", "persist_analytics_evidence_artifact", "YouTubeAnalyticsCoverageError", "diagnose_daily_coverage", "verify_daily_coverage_diagnostic"]
