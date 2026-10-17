namespace UtoAegis.Core.ThreatIntelligence;

public enum ThreatUpdateRejectionReason
{
    None = 0,
    RollbackDetected = 1,
    PublishedInFuture = 2,
    Expired = 3,
    ValidityPeriodTooLong = 4
}

public readonly record struct ThreatUpdateAcceptance
{
    private ThreatUpdateAcceptance(
        bool isAccepted,
        ThreatUpdateRejectionReason rejectionReason)
    {
        IsAccepted = isAccepted;
        RejectionReason = rejectionReason;
    }

    public static ThreatUpdateAcceptance Accepted { get; } =
        new(true, ThreatUpdateRejectionReason.None);

    public bool IsAccepted { get; }

    public ThreatUpdateRejectionReason RejectionReason { get; }

    public static ThreatUpdateAcceptance Reject(ThreatUpdateRejectionReason reason)
    {
        if (reason == ThreatUpdateRejectionReason.None || !Enum.IsDefined(reason))
        {
            throw new ArgumentOutOfRangeException(nameof(reason));
        }

        return new ThreatUpdateAcceptance(false, reason);
    }
}
