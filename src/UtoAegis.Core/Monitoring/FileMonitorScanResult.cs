using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorScanResult(
    string Path,
    FileChangeKind ChangeKind,
    DateTimeOffset ObservedUtc,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    FileScanResult Result);
