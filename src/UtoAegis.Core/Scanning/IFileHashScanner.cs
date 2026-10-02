namespace UtoAegis.Core.Scanning;

/// <summary>
/// Calculates a cryptographic identifier for a file without executing or modifying it.
/// </summary>
public interface IFileHashScanner
{
    ValueTask<FileHashScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default);
}
