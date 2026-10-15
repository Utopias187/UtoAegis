namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorIssue(
    FileMonitorIssueKind Kind,
    string? Path,
    string Message,
    DateTimeOffset ObservedUtc);
