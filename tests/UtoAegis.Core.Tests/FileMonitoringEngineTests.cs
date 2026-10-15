using System.Runtime.CompilerServices;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class FileMonitoringEngineTests
{
    private string _testDirectory = null!;

    [TestInitialize]
    public void CreateTestDirectory()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
    }

    [TestCleanup]
    public void DeleteTestDirectory()
    {
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task RunAsync_BurstForSamePath_DebouncesToOneScan()
    {
        var path = Path.Combine(_testDirectory, "sample.bin");
        await File.WriteAllTextAsync(path, "sample");
        var now = DateTimeOffset.UtcNow;
        var scanner = new StubFileScanner();
        var directoryScanner = new StubDirectoryScanner();
        var sink = new RecordingSink();
        var source = new StubEventSource(
            [
                FileMonitorEvent.FileChanged(path, FileChangeKind.Created, now),
                FileMonitorEvent.FileChanged(path, FileChangeKind.Changed, now.AddMilliseconds(1)),
                FileMonitorEvent.FileChanged(path, FileChangeKind.Changed, now.AddMilliseconds(2))
            ]);
        var engine = new FileMonitoringEngine(
            scanner,
            directoryScanner,
            sink,
            new FileMonitorOptions(TimeSpan.FromMilliseconds(10)));

        var summary = await engine.RunAsync(_testDirectory, source);

        Assert.AreEqual(3L, summary.EventCount);
        Assert.AreEqual(1L, summary.FileScanCount);
        Assert.AreEqual(1L, summary.RecoveryScanCount);
        Assert.AreEqual(1, scanner.ScanCount);
        Assert.HasCount(1, sink.FileScans);
        Assert.AreEqual(FileChangeKind.Changed, sink.FileScans[0].ChangeKind);
        Assert.HasCount(1, sink.RecoveryScans);
        Assert.AreEqual(MonitorRecoveryReason.InitialScan, sink.RecoveryScans[0].Reason);
    }

    [TestMethod]
    public async Task RunAsync_Overflow_DiscardsPendingAndRunsRecoveryScan()
    {
        var path = Path.Combine(_testDirectory, "sample.bin");
        await File.WriteAllTextAsync(path, "sample");
        var now = DateTimeOffset.UtcNow;
        var scanner = new StubFileScanner();
        var directoryScanner = new StubDirectoryScanner();
        var sink = new RecordingSink();
        var source = new StubEventSource(
            [
                FileMonitorEvent.FileChanged(path, FileChangeKind.Changed, now),
                FileMonitorEvent.Overflow(now.AddMilliseconds(1), "Synthetic overflow.")
            ]);
        var engine = new FileMonitoringEngine(
            scanner,
            directoryScanner,
            sink,
            new FileMonitorOptions(TimeSpan.FromSeconds(1), runInitialScan: false));

        var summary = await engine.RunAsync(_testDirectory, source);

        Assert.AreEqual(0L, summary.FileScanCount);
        Assert.AreEqual(1L, summary.RecoveryScanCount);
        Assert.AreEqual(1L, summary.IssueCount);
        Assert.AreEqual(0, scanner.ScanCount);
        Assert.HasCount(1, sink.RecoveryScans);
        Assert.AreEqual(MonitorRecoveryReason.EventOverflow, sink.RecoveryScans[0].Reason);
        Assert.AreEqual(FileMonitorIssueKind.EventOverflow, sink.Issues[0].Kind);
    }

    [TestMethod]
    public async Task RunAsync_PathOutsideRoot_IsReportedAndNotScanned()
    {
        var outsidePath = Path.Combine(Path.GetDirectoryName(_testDirectory)!, "outside.bin");
        await File.WriteAllTextAsync(outsidePath, "sample");
        try
        {
            var scanner = new StubFileScanner();
            var sink = new RecordingSink();
            var source = new StubEventSource(
                [FileMonitorEvent.FileChanged(
                    outsidePath,
                    FileChangeKind.Changed,
                    DateTimeOffset.UtcNow)]);
            var engine = new FileMonitoringEngine(
                scanner,
                new StubDirectoryScanner(),
                sink,
                new FileMonitorOptions(TimeSpan.Zero, runInitialScan: false));

            var summary = await engine.RunAsync(_testDirectory, source);

            Assert.AreEqual(0L, summary.FileScanCount);
            Assert.AreEqual(1L, summary.IssueCount);
            Assert.AreEqual(FileMonitorIssueKind.OutsideRoot, sink.Issues[0].Kind);
        }
        finally
        {
            File.Delete(outsidePath);
        }
    }

    [TestMethod]
    public async Task RunAsync_DisappearedFile_IsReportedAndNotScanned()
    {
        var path = Path.Combine(_testDirectory, "missing.bin");
        var scanner = new StubFileScanner();
        var sink = new RecordingSink();
        var source = new StubEventSource(
            [FileMonitorEvent.FileChanged(path, FileChangeKind.Changed, DateTimeOffset.UtcNow)]);
        var engine = new FileMonitoringEngine(
            scanner,
            new StubDirectoryScanner(),
            sink,
            new FileMonitorOptions(TimeSpan.Zero, runInitialScan: false));

        var summary = await engine.RunAsync(_testDirectory, source);

        Assert.AreEqual(0L, summary.FileScanCount);
        Assert.AreEqual(1L, summary.IssueCount);
        Assert.AreEqual(FileMonitorIssueKind.EntryUnavailable, sink.Issues[0].Kind);
    }

    [TestMethod]
    public async Task RunAsync_SourceError_IsReportedWithoutRecoveryScan()
    {
        var sink = new RecordingSink();
        var source = new StubEventSource(
            [FileMonitorEvent.SourceError(DateTimeOffset.UtcNow, "Synthetic error.")]);
        var engine = new FileMonitoringEngine(
            new StubFileScanner(),
            new StubDirectoryScanner(),
            sink,
            new FileMonitorOptions(TimeSpan.Zero, runInitialScan: false));

        var summary = await engine.RunAsync(_testDirectory, source);

        Assert.AreEqual(1L, summary.IssueCount);
        Assert.AreEqual(0L, summary.RecoveryScanCount);
        Assert.AreEqual(FileMonitorIssueKind.SourceError, sink.Issues[0].Kind);
    }

    private sealed class StubEventSource(IReadOnlyList<FileMonitorEvent> events)
        : IFileMonitorEventSource
    {
        public async IAsyncEnumerable<FileMonitorEvent> ReadAllAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var monitorEvent in events)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return monitorEvent;
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class StubFileScanner : IFileScanner
    {
        public int ScanCount { get; private set; }

        public ValueTask<FileScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanCount++;
            var result = new FileScanResult(
                FileHashScanResult.Success(
                    path,
                    new string('a', 64),
                    new FileInfo(path).Length,
                    TimeSpan.Zero),
                Reputation: null,
                Signatures: null);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class StubDirectoryScanner : IDirectoryScanner
    {
        public ValueTask<DirectoryScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(DirectoryScanResult.Finished(
                Path.GetFullPath(path),
                files: [],
                issues: [],
                TimeSpan.Zero));
        }
    }

    private sealed class RecordingSink : IFileMonitorSink
    {
        public List<FileMonitorScanResult> FileScans { get; } = [];

        public List<FileMonitorRecoveryResult> RecoveryScans { get; } = [];

        public List<FileMonitorIssue> Issues { get; } = [];

        public ValueTask FileScannedAsync(
            FileMonitorScanResult result,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileScans.Add(result);
            return ValueTask.CompletedTask;
        }

        public ValueTask RecoveryScanCompletedAsync(
            FileMonitorRecoveryResult result,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RecoveryScans.Add(result);
            return ValueTask.CompletedTask;
        }

        public ValueTask IssueAsync(
            FileMonitorIssue issue,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Issues.Add(issue);
            return ValueTask.CompletedTask;
        }
    }
}
