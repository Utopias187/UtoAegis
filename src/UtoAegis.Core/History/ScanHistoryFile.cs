using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.History;

public sealed record ScanHistoryFile(
    string Path,
    FileHashScanStatus HashStatus,
    string? Sha256,
    long? FileSizeBytes,
    bool Detected,
    bool Completed,
    HashReputationStatus? ReputationStatus,
    ThreatClassification? ReputationClassification,
    string? ReputationMalwareFamily,
    string? ReputationSource,
    DateTimeOffset? ReputationFirstSeenUtc,
    SignatureScanStatus? SignatureStatus,
    string? SignatureEngine,
    IReadOnlyList<ScanHistorySignatureMatch> SignatureMatches,
    string? HashError,
    string? ReputationError,
    string? SignatureError)
{
    public static ScanHistoryFile FromResult(string path, FileScanResult result)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(result);

        return new ScanHistoryFile(
            path,
            result.FileHash.Status,
            result.FileHash.Sha256,
            result.FileHash.FileSizeBytes,
            result.IsDetected,
            result.IsCompleted,
            result.Reputation?.Status,
            result.Reputation?.Indicator?.Classification,
            result.Reputation?.Indicator?.MalwareFamily,
            result.Reputation?.Indicator?.Source,
            result.Reputation?.Indicator?.FirstSeenUtc,
            result.Signatures?.Status,
            result.Signatures?.EngineName,
            result.Signatures?.Matches
                .Select(match => new ScanHistorySignatureMatch(
                    match.RuleId,
                    match.RuleName,
                    match.Source,
                    match.Offset,
                    match.PatternLengthBytes))
                .ToArray() ?? [],
            result.FileHash.ErrorMessage,
            result.Reputation?.ErrorMessage,
            result.Signatures?.ErrorMessage);
    }
}
