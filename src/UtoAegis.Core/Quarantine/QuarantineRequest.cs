using UtoAegis.Core.Reputation;

namespace UtoAegis.Core.Quarantine;

public sealed record QuarantineRequest
{
    public const int MaximumEvidenceCount = 64;
    public const int MaximumEvidenceLength = 200;

    public QuarantineRequest(
        string sourcePath,
        string expectedSha256,
        long expectedLength,
        IReadOnlyCollection<string> detectionEvidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        if (!MalwareHashIndicator.TryNormalizeSha256(expectedSha256, out var normalizedHash))
        {
            throw new ArgumentException(
                "Expected SHA-256 must contain exactly 64 hexadecimal characters.",
                nameof(expectedSha256));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(expectedLength);
        ArgumentNullException.ThrowIfNull(detectionEvidence);
        var normalizedEvidence = detectionEvidence
            .Select(value => value?.Trim())
            .ToArray();
        if (normalizedEvidence.Length is 0 or > MaximumEvidenceCount ||
            normalizedEvidence.Any(value =>
                string.IsNullOrWhiteSpace(value) ||
                value.Length > MaximumEvidenceLength ||
                value.Any(char.IsControl)))
        {
            throw new ArgumentException(
                $"Detection evidence requires 1 to {MaximumEvidenceCount} printable values " +
                $"of at most {MaximumEvidenceLength} characters.",
                nameof(detectionEvidence));
        }

        SourcePath = Path.GetFullPath(sourcePath);
        ExpectedSha256 = normalizedHash!;
        ExpectedLength = expectedLength;
        DetectionEvidence = normalizedEvidence
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .Select(value => value!)
            .ToArray();
    }

    public string SourcePath { get; }

    public string ExpectedSha256 { get; }

    public long ExpectedLength { get; }

    public IReadOnlyList<string> DetectionEvidence { get; }
}
