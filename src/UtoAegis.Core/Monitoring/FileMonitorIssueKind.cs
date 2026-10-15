namespace UtoAegis.Core.Monitoring;

public enum FileMonitorIssueKind
{
    EventOverflow,
    SourceError,
    OutsideRoot,
    ReparsePointSkipped,
    NotARegularFile,
    EntryUnavailable
}
