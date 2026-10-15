namespace UtoAegis.Core.Scanning;

public sealed record DirectoryScanIssue(
    string Path,
    DirectoryScanIssueKind Kind,
    string Message);
