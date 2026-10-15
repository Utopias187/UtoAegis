namespace UtoAegis.Core.History;

public interface IScanHistoryStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken = default);

    ValueTask AppendAsync(
        ScanHistoryRecord record,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<ScanHistorySummary>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default);

    ValueTask<ScanHistoryRecord?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    ValueTask<ScanHistoryPruneResult> PruneAsync(
        DateTimeOffset completedBeforeUtc,
        CancellationToken cancellationToken = default);
}
