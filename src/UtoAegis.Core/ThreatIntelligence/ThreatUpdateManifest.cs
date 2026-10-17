namespace UtoAegis.Core.ThreatIntelligence;

public sealed record ThreatUpdateManifest
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256";
    public const int MaximumIdentifierLength = 64;

    public ThreatUpdateManifest(
        long sequence,
        string version,
        string keyId,
        DateTimeOffset publishedUtc,
        DateTimeOffset expiresUtc,
        IReadOnlyCollection<ThreatContentDescriptor> contents)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(contents);

        ValidateIdentifier(version, nameof(version));
        ValidateIdentifier(keyId, nameof(keyId));

        var normalizedPublishedUtc = publishedUtc.ToUniversalTime();
        var normalizedExpiresUtc = expiresUtc.ToUniversalTime();
        if (normalizedExpiresUtc <= normalizedPublishedUtc)
        {
            throw new ArgumentException(
                "The expiration time must be later than the publication time.",
                nameof(expiresUtc));
        }

        var normalizedContents = contents
            .OrderBy(content => content.Kind)
            .ToArray();
        if (normalizedContents.Length != 2 ||
            normalizedContents.Select(content => content.Kind).Distinct().Count() != 2 ||
            !normalizedContents.Any(content => content.Kind == ThreatContentKind.HashIndicators) ||
            !normalizedContents.Any(content => content.Kind == ThreatContentKind.ByteSignatures))
        {
            throw new ArgumentException(
                "A threat update must contain exactly one hash-indicator payload and one byte-signature payload.",
                nameof(contents));
        }

        Sequence = sequence;
        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        Version = version;
        KeyId = keyId;
        PublishedUtc = normalizedPublishedUtc;
        ExpiresUtc = normalizedExpiresUtc;
        Contents = normalizedContents;
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public long Sequence { get; }

    public string Version { get; }

    public string KeyId { get; }

    public DateTimeOffset PublishedUtc { get; }

    public DateTimeOffset ExpiresUtc { get; }

    public IReadOnlyList<ThreatContentDescriptor> Contents { get; }

    private static void ValidateIdentifier(string value, string parameterName)
    {
        if (value.Length > MaximumIdentifierLength ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException(
                $"The identifier must contain 1 to {MaximumIdentifierLength} ASCII letters, digits, dots, dashes, or underscores, and must start and end with a letter or digit.",
                parameterName);
        }
    }
}
