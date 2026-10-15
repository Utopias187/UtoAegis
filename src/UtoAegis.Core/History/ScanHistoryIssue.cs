using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.History;

public sealed record ScanHistoryIssue(
    string Path,
    DirectoryScanIssueKind Kind,
    string Message);
