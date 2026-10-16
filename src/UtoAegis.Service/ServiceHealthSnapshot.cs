namespace UtoAegis.Service;

internal sealed record ServiceHealthSnapshot(
    long ScannedFileCount,
    long DetectionCount,
    long QuarantinedFileCount,
    long ResponseFailureCount,
    long MonitorIssueCount,
    long HistoryFailureCount);
