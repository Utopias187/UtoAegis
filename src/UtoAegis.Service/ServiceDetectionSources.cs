using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal sealed record ServiceDetectionSources(
    string? DatabasePath,
    string? SignaturePath,
    bool IsManagedContent,
    string? ContentVersion,
    long? ContentSequence,
    string? SigningKeyId,
    DateTimeOffset? ExpiresUtc)
{
    public static async ValueTask<ServiceDetectionSources> ResolveAsync(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.ContentStorePath is null)
        {
            return new ServiceDetectionSources(
                configuration.DatabasePath,
                configuration.SignaturePath,
                false,
                null,
                null,
                null,
                null);
        }

        var trustStore = await ThreatTrustStoreFileLoader.LoadAsync(
            configuration.TrustedSigningKeyPaths,
            cancellationToken).ConfigureAwait(false);
        var verifier = new SignedThreatBundleVerifier(trustStore);
        var contentStore = new ThreatContentStore(configuration.ContentStorePath, verifier);
        var snapshot = await contentStore.GetActiveReadOnlyAsync(cancellationToken)
            .ConfigureAwait(false);
        return new ServiceDetectionSources(
            snapshot.ReputationDatabasePath,
            snapshot.SignatureRulesPath,
            true,
            snapshot.Manifest.Version,
            snapshot.Manifest.Sequence,
            snapshot.Manifest.KeyId,
            snapshot.Manifest.ExpiresUtc);
    }
}
