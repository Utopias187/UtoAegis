namespace UtoAegis.Core.Scanning;

/// <summary>
/// Discovers and scans files beneath one directory without following reparse points.
/// </summary>
public interface IDirectoryScanner
{
    ValueTask<DirectoryScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default);
}
