using UtoAegis.Core.Reputation;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Scanning;

public sealed record FileScanResult(
    FileHashScanResult FileHash,
    HashReputationResult? Reputation,
    SignatureScanResult? Signatures)
{
    public string? Path => FileHash.Path ?? Signatures?.Path;

    public bool IsDetected =>
        Reputation?.Status == HashReputationStatus.Malicious ||
        Signatures?.Status == SignatureScanStatus.Detected;

    public bool IsCompleted =>
        FileHash.IsSuccess &&
        Reputation?.Status != HashReputationStatus.LookupFailed &&
        (Signatures is null || Signatures.IsCompleted);
}
