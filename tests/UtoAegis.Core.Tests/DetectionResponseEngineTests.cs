using UtoAegis.Core.Quarantine;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class DetectionResponseEngineTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public async Task RespondAsync_DefaultPolicy_ObservesWithoutMutation()
    {
        var store = new StubQuarantineStore();
        var engine = new DetectionResponseEngine(new ResponsePolicy(), store);

        var decision = await engine.RespondAsync(DetectedScan("sample.bin"));

        Assert.AreEqual(ResponseDecisionKind.ObserveOnly, decision.Kind);
        Assert.IsFalse(decision.ChangedSystemState);
        Assert.AreEqual(0, store.QuarantineCount);
    }

    [TestMethod]
    public async Task RespondAsync_DryRun_DoesNotMutate()
    {
        var store = new StubQuarantineStore();
        var policy = new ResponsePolicy(ResponseMode.DryRunQuarantine);
        var engine = new DetectionResponseEngine(policy, store);

        var decision = await engine.RespondAsync(DetectedScan("sample.bin"));

        Assert.AreEqual(ResponseDecisionKind.DryRun, decision.Kind);
        Assert.AreEqual(0, store.QuarantineCount);
    }

    [TestMethod]
    public async Task RespondAsync_AllowlistedHash_TakesPriorityOverQuarantine()
    {
        var store = new StubQuarantineStore();
        var policy = new ResponsePolicy(
            ResponseMode.Quarantine,
            allowlistedSha256: [Hash.ToUpperInvariant()]);
        var engine = new DetectionResponseEngine(policy, store);

        var decision = await engine.RespondAsync(DetectedScan("sample.bin"));

        Assert.AreEqual(ResponseDecisionKind.AllowlistedHash, decision.Kind);
        Assert.AreEqual(0, store.QuarantineCount);
    }

    [TestMethod]
    public async Task RespondAsync_AllowlistedPath_RequiresPathBoundary()
    {
        var parent = Path.Combine(Path.GetTempPath(), "UtoAegis.Tests", "safe");
        var store = new StubQuarantineStore();
        var policy = new ResponsePolicy(
            ResponseMode.Quarantine,
            allowlistedPathPrefixes: [parent]);
        var engine = new DetectionResponseEngine(policy, store);

        var allowed = await engine.RespondAsync(DetectedScan(Path.Combine(parent, "sample.bin")));
        var sibling = await engine.RespondAsync(DetectedScan(parent + "ty" + Path.DirectorySeparatorChar + "sample.bin"));

        Assert.AreEqual(ResponseDecisionKind.AllowlistedPath, allowed.Kind);
        Assert.AreEqual(ResponseDecisionKind.Quarantined, sibling.Kind);
        Assert.AreEqual(1, store.QuarantineCount);
    }

    [TestMethod]
    public async Task RespondAsync_QuarantineMode_DelegatesVerifiedIdentityAndEvidence()
    {
        var store = new StubQuarantineStore();
        var engine = new DetectionResponseEngine(
            new ResponsePolicy(ResponseMode.Quarantine),
            store);

        var decision = await engine.RespondAsync(DetectedScan("sample.bin"));

        Assert.AreEqual(ResponseDecisionKind.Quarantined, decision.Kind);
        Assert.IsTrue(decision.ChangedSystemState);
        Assert.IsNotNull(store.LastRequest);
        Assert.AreEqual(Hash, store.LastRequest.ExpectedSha256);
        Assert.AreEqual(12L, store.LastRequest.ExpectedLength);
        CollectionAssert.Contains(store.LastRequest.DetectionEvidence.ToArray(), "hash-reputation");
    }

    [TestMethod]
    public async Task RespondAsync_AtActionLimit_RefusesAdditionalQuarantine()
    {
        var store = new StubQuarantineStore();
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var policy = new ResponsePolicy(
            ResponseMode.Quarantine,
            maxActionsPerWindow: 1,
            rateLimitWindow: TimeSpan.FromMinutes(5));
        var engine = new DetectionResponseEngine(policy, store, time);

        var first = await engine.RespondAsync(DetectedScan("first.bin"));
        var limited = await engine.RespondAsync(DetectedScan("second.bin"));
        time.Advance(TimeSpan.FromMinutes(5));
        var afterWindow = await engine.RespondAsync(DetectedScan("third.bin"));

        Assert.AreEqual(ResponseDecisionKind.Quarantined, first.Kind);
        Assert.AreEqual(ResponseDecisionKind.RateLimited, limited.Kind);
        Assert.AreEqual(ResponseDecisionKind.Quarantined, afterWindow.Kind);
        Assert.AreEqual(2, store.QuarantineCount);
    }

    [TestMethod]
    public async Task RespondAsync_IncompleteScan_RefusesResponse()
    {
        var store = new StubQuarantineStore();
        var engine = new DetectionResponseEngine(
            new ResponsePolicy(ResponseMode.Quarantine),
            store);
        var failed = new FileScanResult(
            FileHashScanResult.Failure(
                FileHashScanStatus.AccessDenied,
                "sample.bin",
                TimeSpan.Zero,
                "denied"),
            Reputation: null,
            Signatures: null);

        var decision = await engine.RespondAsync(failed);

        Assert.AreEqual(ResponseDecisionKind.ScanIncomplete, decision.Kind);
        Assert.AreEqual(0, store.QuarantineCount);
    }

    [TestMethod]
    public void Constructor_QuarantineWithoutStore_Throws()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new DetectionResponseEngine(new ResponsePolicy(ResponseMode.Quarantine)));
    }

    [TestMethod]
    public void Policy_InvalidHashAndRateLimits_Throw()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new ResponsePolicy(allowlistedSha256: ["invalid"]));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new ResponsePolicy(maxActionsPerWindow: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new ResponsePolicy(rateLimitWindow: TimeSpan.FromDays(2)));
    }

    private static FileScanResult DetectedScan(string path)
    {
        var created = MalwareHashIndicator.TryCreate(
            Hash,
            ThreatClassification.Malware,
            "test",
            malwareFamily: null,
            firstSeenUtc: null,
            out var indicator,
            out var error);
        Assert.IsTrue(created, error);
        return new FileScanResult(
            FileHashScanResult.Success(path, Hash, 12, TimeSpan.Zero),
            HashReputationResult.Malicious(indicator!, DateTimeOffset.UtcNow),
            Signatures: null);
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan amount) => now += amount;
    }

    private sealed class StubQuarantineStore : IQuarantineStore
    {
        public int QuarantineCount { get; private set; }

        public QuarantineRequest? LastRequest { get; private set; }

        public ValueTask InitializeAsync(CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<QuarantineOperationResult> QuarantineAsync(
            QuarantineRequest request,
            CancellationToken cancellationToken = default)
        {
            QuarantineCount++;
            LastRequest = request;
            return ValueTask.FromResult(new QuarantineOperationResult(
                QuarantineOperationStatus.Quarantined,
                Entry: null,
                ErrorMessage: null));
        }

        public ValueTask<IReadOnlyList<QuarantineEntry>> ListAsync(
            int limit,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IReadOnlyList<QuarantineEntry>>([]);

        public ValueTask<QuarantineEntry?> GetAsync(
            Guid id,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<QuarantineEntry?>(null);

        public ValueTask<RestoreOperationResult> RestoreAsync(
            Guid id,
            string? destinationPath = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
