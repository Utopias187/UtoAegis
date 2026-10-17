namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatTrustStore
{
    private readonly IReadOnlyDictionary<string, TrustedThreatSigningKey> _keys;

    public ThreatTrustStore(IReadOnlyCollection<TrustedThreatSigningKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Count is 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keys),
                "The trust store must contain between 1 and 32 signing keys.");
        }

        var normalized = new Dictionary<string, TrustedThreatSigningKey>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (!normalized.TryAdd(key.KeyId, key))
            {
                throw new ArgumentException(
                    $"The trust store contains duplicate key id '{key.KeyId}'.",
                    nameof(keys));
            }
        }

        _keys = normalized;
    }

    public IReadOnlyCollection<string> KeyIds => _keys.Keys.ToArray();

    internal bool TryGetKey(string keyId, out TrustedThreatSigningKey? key) =>
        _keys.TryGetValue(keyId, out key);
}
