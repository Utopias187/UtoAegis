namespace UtoAegis.Core.Quarantine;

public sealed record RestoreOperationResult(
    RestoreOperationStatus Status,
    QuarantineEntry? Entry,
    string? DestinationPath,
    string? ErrorMessage)
{
    public bool IsSuccess => Status == RestoreOperationStatus.Restored;
}
