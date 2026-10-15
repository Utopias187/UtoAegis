namespace UtoAegis.Core.Scanning;

public enum DirectoryScanIssueKind
{
    AccessDenied,
    Excluded,
    ReparsePointSkipped,
    DepthLimitReached,
    EntryChanged,
    EntryDisappeared,
    IoError
}
