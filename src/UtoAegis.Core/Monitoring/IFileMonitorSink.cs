namespace UtoAegis.Core.Monitoring;

public interface IFileMonitorSink
{
    ValueTask FileScannedAsync(
        FileMonitorScanResult result,
        CancellationToken cancellationToken = default);

    ValueTask RecoveryScanCompletedAsync(
        FileMonitorRecoveryResult result,
        CancellationToken cancellationToken = default);

    ValueTask IssueAsync(
        FileMonitorIssue issue,
        CancellationToken cancellationToken = default);
}
