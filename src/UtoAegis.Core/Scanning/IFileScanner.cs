namespace UtoAegis.Core.Scanning;

/// <summary>
/// Runs the configured detection stages for one file without executing or modifying it.
/// </summary>
public interface IFileScanner
{
    ValueTask<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default);
}
