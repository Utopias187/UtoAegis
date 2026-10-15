namespace UtoAegis.Core.Scanning;

public enum DirectoryScanIssueKind
{
    AccessDenied,
    ReparsePointSkipped,
    DepthLimitReached,
    EntryDisappeared,
    IoError
}
