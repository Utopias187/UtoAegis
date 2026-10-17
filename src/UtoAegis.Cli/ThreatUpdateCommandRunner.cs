using System.Text.Json;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Cli;

internal static class ThreatUpdateCommandRunner
{
    public static async Task<int> ApplyAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = await CreateVerifiedStoreAsync(options, cancellationToken);
        var snapshot = await store.ApplyAsync(options.InputPath!, cancellationToken);
        WriteSnapshot(options, "Activated", snapshot);
        return ExitCodes.Success;
    }

    public static async Task<int> StatusAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = new ThreatContentStore(options.ContentStorePath!);
        var status = await store.GetStatusAsync(cancellationToken);
        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    status = status.HasActiveContent ? "Active" : "Empty",
                    storePath = Path.GetFullPath(options.ContentStorePath!),
                    activeVersion = status.ActiveVersion,
                    activeSequence = status.ActiveSequence,
                    previousVersion = status.PreviousVersion,
                    previousSequence = status.PreviousSequence,
                    highestAcceptedSequence = status.HighestAcceptedSequence
                },
                CliJson.ResultOptions));
        }
        else if (!status.HasActiveContent)
        {
            Console.WriteLine(
                $"No threat content is active in {Path.GetFullPath(options.ContentStorePath!)}.");
        }
        else
        {
            Console.WriteLine(
                $"Active threat content: {status.ActiveVersion} " +
                $"(sequence {status.ActiveSequence}); highest accepted sequence " +
                $"{status.HighestAcceptedSequence}.");
            Console.WriteLine(status.PreviousSequence is null
                ? "No rollback version is available."
                : $"Rollback version: {status.PreviousVersion} " +
                  $"(sequence {status.PreviousSequence}).");
        }

        return ExitCodes.Success;
    }

    public static async Task<int> RollbackAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = await CreateVerifiedStoreAsync(options, cancellationToken);
        var snapshot = await store.RollbackAsync(cancellationToken);
        WriteSnapshot(options, "RolledBack", snapshot);
        return ExitCodes.Success;
    }

    private static async ValueTask<ThreatContentStore> CreateVerifiedStoreAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var specification in options.TrustedKeySpecs)
        {
            var separator = specification.IndexOf('=', StringComparison.Ordinal);
            var keyId = specification[..separator];
            var path = specification[(separator + 1)..];
            if (!paths.TryAdd(keyId, path))
            {
                throw new ThreatUpdateException(
                    $"Trusted signing key id '{keyId}' was supplied more than once.");
            }
        }

        var trustStore = await ThreatTrustStoreFileLoader.LoadAsync(paths, cancellationToken);
        var verifier = new SignedThreatBundleVerifier(trustStore);
        return new ThreatContentStore(options.ContentStorePath!, verifier);
    }

    private static void WriteSnapshot(
        CliOptions options,
        string status,
        ThreatContentSnapshot snapshot)
    {
        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    status,
                    storePath = Path.GetFullPath(options.ContentStorePath!),
                    version = snapshot.Manifest.Version,
                    sequence = snapshot.Manifest.Sequence,
                    publishedUtc = snapshot.Manifest.PublishedUtc,
                    expiresUtc = snapshot.Manifest.ExpiresUtc,
                    signingKeyId = snapshot.Manifest.KeyId
                },
                CliJson.ResultOptions));
        }
        else
        {
            Console.WriteLine(
                $"{status} threat content {snapshot.Manifest.Version} " +
                $"(sequence {snapshot.Manifest.Sequence}, key {snapshot.Manifest.KeyId}).");
        }
    }
}
