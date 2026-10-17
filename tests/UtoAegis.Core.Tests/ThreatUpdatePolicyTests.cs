using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class ThreatUpdatePolicyTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void Evaluate_FreshHigherSequence_AcceptsManifest()
    {
        var result = new ThreatUpdatePolicy().Evaluate(
            CreateManifest(sequence: 8),
            highestAcceptedSequence: 7,
            Now);

        Assert.AreEqual(ThreatUpdateAcceptance.Accepted, result);
    }

    [TestMethod]
    [DataRow(6)]
    [DataRow(7)]
    public void Evaluate_NonIncreasingSequence_RejectsRollback(long sequence)
    {
        var result = new ThreatUpdatePolicy().Evaluate(
            CreateManifest(sequence),
            highestAcceptedSequence: 7,
            Now);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(ThreatUpdateRejectionReason.RollbackDetected, result.RejectionReason);
    }

    [TestMethod]
    public void Evaluate_PublicationBeyondClockSkew_RejectsManifest()
    {
        var result = new ThreatUpdatePolicy().Evaluate(
            CreateManifest(
                publishedUtc: Now.AddMinutes(6),
                expiresUtc: Now.AddDays(1)),
            highestAcceptedSequence: 0,
            Now);

        Assert.AreEqual(ThreatUpdateRejectionReason.PublishedInFuture, result.RejectionReason);
    }

    [TestMethod]
    public void Evaluate_ExpirationBeyondClockSkew_RejectsManifest()
    {
        var result = new ThreatUpdatePolicy().Evaluate(
            CreateManifest(
                publishedUtc: Now.AddDays(-1),
                expiresUtc: Now.AddMinutes(-6)),
            highestAcceptedSequence: 0,
            Now);

        Assert.AreEqual(ThreatUpdateRejectionReason.Expired, result.RejectionReason);
    }

    [TestMethod]
    public void Evaluate_ValidityPeriodAboveLimit_RejectsManifest()
    {
        var result = new ThreatUpdatePolicy().Evaluate(
            CreateManifest(
                publishedUtc: Now.AddDays(-1),
                expiresUtc: Now.AddDays(14)),
            highestAcceptedSequence: 0,
            Now);

        Assert.AreEqual(
            ThreatUpdateRejectionReason.ValidityPeriodTooLong,
            result.RejectionReason);
    }

    [TestMethod]
    public void Evaluate_TimesInsideClockSkew_AcceptsManifest()
    {
        var policy = new ThreatUpdatePolicy();

        var future = policy.Evaluate(
            CreateManifest(
                publishedUtc: Now.AddMinutes(5),
                expiresUtc: Now.AddDays(1)),
            highestAcceptedSequence: 0,
            Now);
        var expired = policy.Evaluate(
            CreateManifest(
                publishedUtc: Now.AddDays(-1),
                expiresUtc: Now.AddMinutes(-5)),
            highestAcceptedSequence: 0,
            Now);

        Assert.IsTrue(future.IsAccepted);
        Assert.IsTrue(expired.IsAccepted);
    }

    [TestMethod]
    public void Constructor_ExcessiveClockSkew_RejectsPolicy()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new ThreatUpdatePolicy(clockSkew: TimeSpan.FromHours(2)));
    }

    private static ThreatUpdateManifest CreateManifest(
        long sequence = 8,
        DateTimeOffset? publishedUtc = null,
        DateTimeOffset? expiresUtc = null) =>
        ThreatUpdateManifestTests.CreateManifest(
            sequence,
            publishedUtc: publishedUtc ?? Now.AddDays(-1),
            expiresUtc: expiresUtc ?? Now.AddDays(1));
}
