namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorSummary(
    long EventCount,
    long FileScanCount,
    long RecoveryScanCount,
    long IssueCount,
    TimeSpan Elapsed);
