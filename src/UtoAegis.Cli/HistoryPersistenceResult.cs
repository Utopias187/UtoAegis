namespace UtoAegis.Cli;

internal sealed record HistoryPersistenceResult(
    bool Requested,
    bool Stored,
    string? DatabasePath,
    string? ErrorMessage);
