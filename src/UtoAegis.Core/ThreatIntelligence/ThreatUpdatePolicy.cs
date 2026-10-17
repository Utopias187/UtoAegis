namespace UtoAegis.Core.ThreatIntelligence;

public sealed record ThreatUpdatePolicy
{
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan DefaultMaximumValidityPeriod = TimeSpan.FromDays(14);
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromHours(1);
    public static readonly TimeSpan MaximumAllowedValidityPeriod = TimeSpan.FromDays(90);

    public ThreatUpdatePolicy(
        TimeSpan? clockSkew = null,
        TimeSpan? maximumValidityPeriod = null)
    {
        ClockSkew = clockSkew ?? DefaultClockSkew;
        MaximumValidityPeriod = maximumValidityPeriod ?? DefaultMaximumValidityPeriod;

        if (ClockSkew < TimeSpan.Zero || ClockSkew > MaximumClockSkew)
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        if (MaximumValidityPeriod <= TimeSpan.Zero ||
            MaximumValidityPeriod > MaximumAllowedValidityPeriod)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumValidityPeriod));
        }
    }

    public TimeSpan ClockSkew { get; }

    public TimeSpan MaximumValidityPeriod { get; }

    public ThreatUpdateAcceptance Evaluate(
        ThreatUpdateManifest manifest,
        long highestAcceptedSequence,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentOutOfRangeException.ThrowIfNegative(highestAcceptedSequence);

        var utcNow = now.ToUniversalTime();
        if (manifest.Sequence <= highestAcceptedSequence)
        {
            return ThreatUpdateAcceptance.Reject(
                ThreatUpdateRejectionReason.RollbackDetected);
        }

        if (manifest.PublishedUtc > utcNow + ClockSkew)
        {
            return ThreatUpdateAcceptance.Reject(
                ThreatUpdateRejectionReason.PublishedInFuture);
        }

        if (manifest.ExpiresUtc < utcNow - ClockSkew)
        {
            return ThreatUpdateAcceptance.Reject(
                ThreatUpdateRejectionReason.Expired);
        }

        if (manifest.ExpiresUtc - manifest.PublishedUtc > MaximumValidityPeriod)
        {
            return ThreatUpdateAcceptance.Reject(
                ThreatUpdateRejectionReason.ValidityPeriodTooLong);
        }

        return ThreatUpdateAcceptance.Accepted;
    }
}
