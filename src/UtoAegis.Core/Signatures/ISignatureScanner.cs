namespace UtoAegis.Core.Signatures;

/// <summary>
/// Scans file content with one configured signature engine.
/// </summary>
public interface ISignatureScanner
{
    string EngineName { get; }

    ValueTask<SignatureScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default);
}
