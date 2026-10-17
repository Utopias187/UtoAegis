using Microsoft.Extensions.Logging.Abstractions;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Quarantine;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Service.Tests;

[TestClass]
public sealed class ServiceFileMonitorSinkTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public async Task FileScannedAsync_ObserveOnly_RecordsDetectionWithoutMutation()
    {
        var history = new StubHistoryStore();
        var quarantine = new StubQuarantineStore();
        var sink = CreateSink(
            new DetectionResponseEngine(new ResponsePolicy(), quarantine),
            history);
        var now = DateTimeOffset.UtcNow;

        await sink.FileScannedAsync(new FileMonitorScanResult(
            "sample.bin",
            FileChangeKind.Created,
            now,
            now,
            now,
            DetectedScan("sample.bin")));

        var health = sink.Snapshot();
        Assert.AreEqual(1L, health.ScannedFileCount);
        Assert.AreEqual(1L, health.DetectionCount);
        Assert.AreEqual(0L, health.QuarantinedFileCount);
        Assert.AreEqual(0, quarantine.QuarantineCount);
        Assert.HasCount(1, history.Records);
    }

    [TestMethod]
    public async Task FileScannedAsync_QuarantineSuccess_UpdatesHealth()
    {
        var quarantine = new StubQuarantineStore();
        var sink = CreateSink(new DetectionResponseEngine(
            new ResponsePolicy(ResponseMode.Quarantine),
            quarantine));
        var now = DateTimeOffset.UtcNow;

        await sink.FileScannedAsync(new FileMonitorScanResult(
            "sample.bin",
            FileChangeKind.Changed,
            now,
            now,
            now,
            DetectedScan("sample.bin")));

        var health = sink.Snapshot();
        Assert.AreEqual(1L, health.QuarantinedFileCount);
        Assert.AreEqual(0L, health.ResponseFailureCount);
        Assert.AreEqual(1, quarantine.QuarantineCount);
    }

    [TestMethod]
    public async Task RecoveryScanCompletedAsync_MissingResultRoot_UsesConfiguredRoot()
    {
        var history = new StubHistoryStore();
        var monitorRoot = Path.GetFullPath("monitored");
        var sink = CreateSink(
            new DetectionResponseEngine(new ResponsePolicy()),
            history,
            monitorRoot,
            recursive: false);
        var now = DateTimeOffset.UtcNow;
        var failure = DirectoryScanResult.Failure(
            DirectoryScanStatus.DirectoryNotFound,
            rootPath: null,
            issues: [],
            TimeSpan.Zero,
            "missing");

        await sink.RecoveryScanCompletedAsync(new FileMonitorRecoveryResult(
            MonitorRecoveryReason.InitialScan,
            now,
            now,
            failure));

        Assert.HasCount(1, history.Records);
        Assert.AreEqual(monitorRoot, history.Records[0].TargetPath);
        Assert.IsFalse(history.Records[0].Recursive);
        Assert.AreEqual(ScanHistoryOutcome.Failed, history.Records[0].Outcome);
    }

    private static ServiceFileMonitorSink CreateSink(
        DetectionResponseEngine responseEngine,
        IScanHistoryStore? historyStore = null,
        string? monitorRoot = null,
        bool recursive = true) =>
        new(
            NullLogger.Instance,
            responseEngine,
            historyStore,
            monitorRoot ?? Path.GetFullPath("monitored"),
            recursive);

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

    private sealed class StubHistoryStore : IScanHistoryStore
    {
        public List<ScanHistoryRecord> Records { get; } = [];

        public ValueTask InitializeAsync(CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask AppendAsync(
            ScanHistoryRecord record,
            CancellationToken cancellationToken = default)
        {
            Records.Add(record);
            return ValueTask.CompletedTask;
        }

        public ValueTask<IReadOnlyList<ScanHistorySummary>> ListAsync(
            int limit,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask<ScanHistoryRecord?> GetAsync(
            Guid id,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask<ScanHistoryPruneResult> PruneAsync(
            DateTimeOffset completedBeforeUtc,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubQuarantineStore : IQuarantineStore
    {
        public int QuarantineCount { get; private set; }

        public ValueTask InitializeAsync(CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<QuarantineOperationResult> QuarantineAsync(
            QuarantineRequest request,
            CancellationToken cancellationToken = default)
        {
            QuarantineCount++;
            return ValueTask.FromResult(new QuarantineOperationResult(
                QuarantineOperationStatus.Quarantined,
                Entry: null,
                ErrorMessage: null));
        }

        public ValueTask<IReadOnlyList<QuarantineEntry>> ListAsync(
            int limit,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask<QuarantineEntry?> GetAsync(
            Guid id,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask<RestoreOperationResult> RestoreAsync(
            Guid id,
            string? destinationPath = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
