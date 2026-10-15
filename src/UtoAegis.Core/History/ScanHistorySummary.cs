namespace UtoAegis.Core.History;

public sealed record ScanHistorySummary(
    Guid Id,
    ScanHistoryTargetKind TargetKind,
    string TargetPath,
    bool Recursive,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    ScanHistoryOutcome Outcome,
    int FileCount,
    int DetectedFileCount,
    int FailedFileCount,
    int IssueCount,
    string? ErrorMessage);
