using UtoAegis.Core.Reputation;

namespace UtoAegis.Core.ThreatIntelligence;

public sealed record ThreatContentDescriptor
{
    public const long MaximumPayloadLength = 512L * 1024 * 1024;

    public ThreatContentDescriptor(
        ThreatContentKind kind,
        string sha256,
        long length)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (!MalwareHashIndicator.TryNormalizeSha256(sha256, out var normalizedHash))
        {
            throw new ArgumentException(
                "Content SHA-256 must contain exactly 64 hexadecimal characters.",
                nameof(sha256));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaximumPayloadLength);

        Kind = kind;
        Sha256 = normalizedHash!;
        Length = length;
    }

    public ThreatContentKind Kind { get; }

    public string FileName => Kind switch
    {
        ThreatContentKind.HashIndicators => "indicators.jsonl",
        ThreatContentKind.ByteSignatures => "signatures.jsonl",
        _ => throw new InvalidOperationException("Unsupported threat-content kind.")
    };

    public string Sha256 { get; }

    public long Length { get; }
}
