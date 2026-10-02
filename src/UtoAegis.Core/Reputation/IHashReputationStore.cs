namespace UtoAegis.Core.Reputation;

public interface IHashReputationStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken = default);

    ValueTask<HashReputationResult> LookupAsync(
        string sha256,
        CancellationToken cancellationToken = default);

    ValueTask<HashImportResult> ImportAsync(
        IReadOnlyCollection<MalwareHashIndicator> indicators,
        CancellationToken cancellationToken = default);
}
