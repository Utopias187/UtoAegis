using UtoAegis.Core.Reputation;

namespace UtoAegis.Core.Quarantine;

public sealed record QuarantineEntry
{
    private QuarantineEntry(
        Guid id,
        QuarantineEntryStatus status,
        string originalPath,
        string sha256,
        long length,
        DateTimeOffset quarantinedUtc,
        DateTimeOffset originalLastWriteUtc,
        IReadOnlyList<string> detectionEvidence,
        string? restoredPath,
        DateTimeOffset? restoredUtc)
    {
        Id = id;
        Status = status;
        OriginalPath = originalPath;
        Sha256 = sha256;
        Length = length;
        QuarantinedUtc = quarantinedUtc;
        OriginalLastWriteUtc = originalLastWriteUtc;
        DetectionEvidence = detectionEvidence;
        RestoredPath = restoredPath;
        RestoredUtc = restoredUtc;
    }

    public Guid Id { get; }

    public QuarantineEntryStatus Status { get; }

    public string OriginalPath { get; }

    public string Sha256 { get; }

    public long Length { get; }

    public DateTimeOffset QuarantinedUtc { get; }

    public DateTimeOffset OriginalLastWriteUtc { get; }

    public IReadOnlyList<string> DetectionEvidence { get; }

    public string? RestoredPath { get; }

    public DateTimeOffset? RestoredUtc { get; }

    public static QuarantineEntry Restore(
        Guid id,
        QuarantineEntryStatus status,
        string originalPath,
        string sha256,
        long length,
        DateTimeOffset quarantinedUtc,
        DateTimeOffset originalLastWriteUtc,
        IReadOnlyList<string> detectionEvidence,
        string? restoredPath = null,
        DateTimeOffset? restoredUtc = null)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A non-empty quarantine ID is required.", nameof(id));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(originalPath);
        if (!MalwareHashIndicator.TryNormalizeSha256(sha256, out var normalizedHash))
        {
            throw new ArgumentException("Stored SHA-256 is invalid.", nameof(sha256));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentNullException.ThrowIfNull(detectionEvidence);
        if (detectionEvidence.Count == 0)
        {
            throw new ArgumentException("Detection evidence is required.", nameof(detectionEvidence));
        }

        if (status == QuarantineEntryStatus.Restored &&
            (string.IsNullOrWhiteSpace(restoredPath) || restoredUtc is null))
        {
            throw new ArgumentException("Restored entries require a path and timestamp.");
        }

        if (status == QuarantineEntryStatus.Active &&
            (restoredPath is not null || restoredUtc is not null))
        {
            throw new ArgumentException("Active entries cannot contain restoration metadata.");
        }

        return new QuarantineEntry(
            id,
            status,
            Path.GetFullPath(originalPath),
            normalizedHash!,
            length,
            quarantinedUtc.ToUniversalTime(),
            originalLastWriteUtc.ToUniversalTime(),
            detectionEvidence.ToArray(),
            restoredPath is null ? null : Path.GetFullPath(restoredPath),
            restoredUtc?.ToUniversalTime());
    }
}
