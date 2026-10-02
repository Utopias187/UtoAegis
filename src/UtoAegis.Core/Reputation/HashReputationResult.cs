namespace UtoAegis.Core.Reputation;

public sealed record HashReputationResult
{
    private HashReputationResult(
        HashReputationStatus status,
        MalwareHashIndicator? indicator,
        DateTimeOffset? recordUpdatedUtc,
        string? errorMessage)
    {
        Status = status;
        Indicator = indicator;
        RecordUpdatedUtc = recordUpdatedUtc;
        ErrorMessage = errorMessage;
    }

    public HashReputationStatus Status { get; }

    public MalwareHashIndicator? Indicator { get; }

    public DateTimeOffset? RecordUpdatedUtc { get; }

    public string? ErrorMessage { get; }

    public static HashReputationResult Malicious(
        MalwareHashIndicator indicator,
        DateTimeOffset recordUpdatedUtc) =>
        new(HashReputationStatus.Malicious, indicator, recordUpdatedUtc, null);

    public static HashReputationResult Unknown() =>
        new(HashReputationStatus.Unknown, null, null, null);

    public static HashReputationResult LookupFailed(string errorMessage) =>
        new(HashReputationStatus.LookupFailed, null, null, errorMessage);
}
