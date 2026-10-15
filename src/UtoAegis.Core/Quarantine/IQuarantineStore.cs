namespace UtoAegis.Core.Quarantine;

public interface IQuarantineStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken = default);

    ValueTask<QuarantineOperationResult> QuarantineAsync(
        QuarantineRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<QuarantineEntry>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default);

    ValueTask<QuarantineEntry?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    ValueTask<RestoreOperationResult> RestoreAsync(
        Guid id,
        string? destinationPath = null,
        CancellationToken cancellationToken = default);
}
