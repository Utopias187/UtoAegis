using UtoAegis.Core.Monitoring;
using UtoAegis.Infrastructure.Monitoring;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class FileSystemWatcherEventSourceTests
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
    public async Task ReadAllAsync_CreatedFile_EmitsFileEvent()
    {
        await using var source = new FileSystemWatcherEventSource(
            _testDirectory,
            includeSubdirectories: false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var events = source.ReadAllAsync(timeout.Token).GetAsyncEnumerator(timeout.Token);
        var moveNext = events.MoveNextAsync().AsTask();
        var path = Path.Combine(_testDirectory, "sample.bin");

        await File.WriteAllTextAsync(path, "sample", timeout.Token);
        Assert.IsTrue(await moveNext);

        Assert.AreEqual(FileMonitorEventKind.FileChanged, events.Current.Kind);
        Assert.AreEqual(Path.GetFullPath(path), events.Current.Path);
        Assert.IsTrue(
            events.Current.ChangeKind is FileChangeKind.Created or FileChangeKind.Changed);
    }

    [TestMethod]
    public async Task DisposeAsync_PendingReader_Completes()
    {
        var source = new FileSystemWatcherEventSource(
            _testDirectory,
            includeSubdirectories: false);
        await using var events = source.ReadAllAsync().GetAsyncEnumerator();
        var moveNext = events.MoveNextAsync().AsTask();

        await source.DisposeAsync();

        Assert.IsFalse(await moveNext);
    }

    [TestMethod]
    public async Task ReadAllAsync_ExcludedFile_DoesNotEmitItsEvents()
    {
        var excludedPath = Path.Combine(_testDirectory, "history.db");
        var allowedPath = Path.Combine(_testDirectory, "sample.bin");
        await using var source = new FileSystemWatcherEventSource(
            _testDirectory,
            includeSubdirectories: false,
            excludedPaths: [excludedPath]);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var events = source.ReadAllAsync(timeout.Token).GetAsyncEnumerator(timeout.Token);
        var moveNext = events.MoveNextAsync().AsTask();

        await File.WriteAllTextAsync(excludedPath, "state", timeout.Token);
        await File.WriteAllTextAsync(allowedPath, "sample", timeout.Token);
        Assert.IsTrue(await moveNext);

        Assert.AreEqual(Path.GetFullPath(allowedPath), events.Current.Path);
    }

    [TestMethod]
    public async Task BoundedQueue_Overflow_EmitsRecoverySignalAfterQueuedEvent()
    {
        var queue = new BoundedFileMonitorEventQueue(1, TimeProvider.System);
        var now = DateTimeOffset.UtcNow;
        Assert.IsTrue(queue.TryPublish(FileMonitorEvent.FileChanged(
            "first.bin",
            FileChangeKind.Created,
            now)));
        Assert.IsFalse(queue.TryPublish(FileMonitorEvent.FileChanged(
            "dropped.bin",
            FileChangeKind.Changed,
            now)));
        queue.Complete();

        var events = new List<FileMonitorEvent>();
        await foreach (var monitorEvent in queue.ReadAllAsync())
        {
            events.Add(monitorEvent);
        }

        Assert.HasCount(2, events);
        Assert.AreEqual(FileMonitorEventKind.FileChanged, events[0].Kind);
        Assert.AreEqual(FileMonitorEventKind.Overflow, events[1].Kind);
    }

    [TestMethod]
    public void Constructor_MissingRoot_ThrowsDirectoryNotFoundException()
    {
        Assert.ThrowsExactly<DirectoryNotFoundException>(() =>
            new FileSystemWatcherEventSource(
                Path.Combine(_testDirectory, "missing"),
                includeSubdirectories: false));
    }

    [TestMethod]
    public void Constructor_QueueCapacityAboveLimit_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new FileSystemWatcherEventSource(
                _testDirectory,
                includeSubdirectories: false,
                FileSystemWatcherEventSource.MaximumQueueCapacity + 1));
    }
}
