namespace UtoAegis.Core.Reputation;

public sealed record HashImportResult(
    int ProcessedCount,
    int ChangedCount,
    int UnchangedCount);
