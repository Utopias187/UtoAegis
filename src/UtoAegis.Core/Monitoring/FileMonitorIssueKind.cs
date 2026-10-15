namespace UtoAegis.Core.Monitoring;

public enum FileMonitorIssueKind
{
    EventOverflow,
    SourceError,
    Excluded,
    OutsideRoot,
    ReparsePointSkipped,
    NotARegularFile,
    EntryUnavailable
}
