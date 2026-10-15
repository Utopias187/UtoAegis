namespace UtoAegis.Core.Quarantine;

public sealed record QuarantineOperationResult(
    QuarantineOperationStatus Status,
    QuarantineEntry? Entry,
    string? ErrorMessage)
{
    public bool IsSuccess => Status == QuarantineOperationStatus.Quarantined;
}
