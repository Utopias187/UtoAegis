using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class DirectoryScannerTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
    public async Task ScanAsync_DefaultMode_ScansOnlyTopLevelFiles()
    {
        var topLevel = await CreateFileAsync("top.txt");
        await CreateFileAsync(Path.Combine("nested", "child.txt"));
        var fileScanner = new RecordingFileScanner();
        var scanner = new DirectoryScanner(fileScanner);

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Completed, result.Status);
        Assert.HasCount(1, result.Files);
        Assert.AreEqual(topLevel, result.Files[0].Path);
        Assert.HasCount(1, fileScanner.Paths);
    }

    [TestMethod]
    public async Task ScanAsync_RecursiveMode_ScansNestedFilesInStableOrder()
    {
        var paths = new[]
        {
            await CreateFileAsync("z.txt"),
            await CreateFileAsync(Path.Combine("nested", "b.txt")),
            await CreateFileAsync(Path.Combine("nested", "a.txt"))
        };
        var scanner = new DirectoryScanner(
            new RecordingFileScanner(delaySelector: path => Path.GetFileName(path) == "a.txt" ? 40 : 1),
            new DirectoryScanOptions(recurse: true, maximumConcurrency: 3));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Completed, result.Status);
        CollectionAssert.AreEqual(
            paths.OrderBy(path => path, StringComparer.Ordinal).ToArray(),
            result.Files.Select(file => file.Path).ToArray());
    }

    [TestMethod]
    public async Task ScanAsync_ParallelWork_RespectsConcurrencyLimit()
    {
        for (var index = 0; index < 8; index++)
        {
            await CreateFileAsync($"file-{index:D2}.txt");
        }

        var fileScanner = new RecordingFileScanner(delaySelector: _ => 40);
        var scanner = new DirectoryScanner(
            fileScanner,
            new DirectoryScanOptions(maximumConcurrency: 2));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Completed, result.Status);
        Assert.HasCount(8, result.Files);
        Assert.AreEqual(2, fileScanner.MaximumObservedConcurrency);
    }

    [TestMethod]
    public async Task ScanAsync_PerFileFailure_ReturnsPartialResult()
    {
        await CreateFileAsync("good.txt");
        await CreateFileAsync("failed.txt");
        var fileScanner = new RecordingFileScanner(resultSelector: path =>
            Path.GetFileName(path) == "failed.txt"
                ? FailedFile(path)
                : SuccessfulFile(path));
        var scanner = new DirectoryScanner(fileScanner);

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Partial, result.Status);
        Assert.AreEqual(1, result.FailedFileCount);
        Assert.IsTrue(result.IsCompleted);
    }

    [TestMethod]
    public async Task ScanAsync_FileLimitExceeded_DoesNotScanPartialSet()
    {
        await CreateFileAsync("one.txt");
        await CreateFileAsync("two.txt");
        await CreateFileAsync("three.txt");
        var fileScanner = new RecordingFileScanner();
        var scanner = new DirectoryScanner(
            fileScanner,
            new DirectoryScanOptions(maximumFileCount: 2));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.FileLimitExceeded, result.Status);
        Assert.IsFalse(result.IsCompleted);
        Assert.IsEmpty(result.Files);
        Assert.IsEmpty(fileScanner.Paths);
    }

    [TestMethod]
    public async Task ScanAsync_DirectoryLimitExceeded_DoesNotScanPartialSet()
    {
        await CreateFileAsync("top.txt");
        Directory.CreateDirectory(Path.Combine(_testDirectory, "nested"));
        var fileScanner = new RecordingFileScanner();
        var scanner = new DirectoryScanner(
            fileScanner,
            new DirectoryScanOptions(recurse: true, maximumDirectoryCount: 1));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.DirectoryLimitExceeded, result.Status);
        Assert.IsEmpty(result.Files);
        Assert.IsEmpty(fileScanner.Paths);
    }

    [TestMethod]
    public async Task ScanAsync_DepthLimitReached_ReportsSkippedDirectory()
    {
        await CreateFileAsync("top.txt");
        var nested = Path.Combine(_testDirectory, "nested");
        await CreateFileAsync(Path.Combine("nested", "child.txt"));
        var scanner = new DirectoryScanner(
            new RecordingFileScanner(),
            new DirectoryScanOptions(recurse: true, maximumDepth: 0));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Partial, result.Status);
        Assert.HasCount(1, result.Files);
        Assert.HasCount(1, result.Issues);
        Assert.AreEqual(nested, result.Issues[0].Path);
        Assert.AreEqual(DirectoryScanIssueKind.DepthLimitReached, result.Issues[0].Kind);
    }

    [TestMethod]
    public async Task ScanAsync_ReparsePoint_IsSkippedAndReported()
    {
        var target = Path.Combine(_testDirectory, "target");
        Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "target.txt"), "target");
        var link = Path.Combine(_testDirectory, "link");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            Assert.Inconclusive("Symbolic links are unavailable in this test environment.");
        }

        var scanner = new DirectoryScanner(
            new RecordingFileScanner(),
            new DirectoryScanOptions(recurse: true));

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(DirectoryScanStatus.Partial, result.Status);
        Assert.IsTrue(result.Issues.Any(issue =>
            issue.Path == link && issue.Kind == DirectoryScanIssueKind.ReparsePointSkipped));
        Assert.IsFalse(result.Files.Any(file => file.Path.StartsWith(
            link + Path.DirectorySeparatorChar,
            StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task ScanAsync_MissingDirectory_ReturnsExplicitFailure()
    {
        var scanner = new DirectoryScanner(new RecordingFileScanner());

        var result = await scanner.ScanAsync(Path.Combine(_testDirectory, "missing"));

        Assert.AreEqual(DirectoryScanStatus.DirectoryNotFound, result.Status);
        Assert.IsFalse(result.IsCompleted);
    }

    [TestMethod]
    public async Task ScanAsync_FilePath_ReturnsNotADirectory()
    {
        var file = await CreateFileAsync("file.txt");
        var scanner = new DirectoryScanner(new RecordingFileScanner());

        var result = await scanner.ScanAsync(file);

        Assert.AreEqual(DirectoryScanStatus.NotADirectory, result.Status);
    }

    [TestMethod]
    public async Task ScanAsync_PreCancelledToken_ThrowsCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var scanner = new DirectoryScanner(new RecordingFileScanner());

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await scanner.ScanAsync(_testDirectory, cancellation.Token));
    }

    [TestMethod]
    public void Options_OutOfRangeValues_Throw()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DirectoryScanOptions(maximumConcurrency: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DirectoryScanOptions(
                maximumConcurrency: DirectoryScanOptions.MaximumAllowedConcurrency + 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DirectoryScanOptions(maximumFileCount: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DirectoryScanOptions(maximumDirectoryCount: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DirectoryScanOptions(maximumDepth: -1));
    }

    private async Task<string> CreateFileAsync(string relativePath)
    {
        var path = Path.Combine(_testDirectory, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, relativePath);
        return path;
    }

    private static FileScanResult SuccessfulFile(string path) =>
        new(
            FileHashScanResult.Success(path, Hash, 1, TimeSpan.Zero),
            Reputation: null,
            Signatures: null);

    private static FileScanResult FailedFile(string path) =>
        new(
            FileHashScanResult.Failure(
                FileHashScanStatus.IoError,
                path,
                TimeSpan.Zero,
                "failed"),
            Reputation: null,
            Signatures: null);

    private sealed class RecordingFileScanner(
        Func<string, FileScanResult>? resultSelector = null,
        Func<string, int>? delaySelector = null) : IFileScanner
    {
        private readonly Func<string, FileScanResult> _resultSelector =
            resultSelector ?? SuccessfulFile;
        private readonly Func<string, int> _delaySelector = delaySelector ?? (_ => 0);
        private readonly List<string> _paths = [];
        private readonly object _pathsLock = new();
        private int _activeScans;
        private int _maximumObservedConcurrency;

        public IReadOnlyList<string> Paths
        {
            get
            {
                lock (_pathsLock)
                {
                    return _paths.ToArray();
                }
            }
        }

        public int MaximumObservedConcurrency => _maximumObservedConcurrency;

        public async ValueTask<FileScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            lock (_pathsLock)
            {
                _paths.Add(path);
            }

            var active = Interlocked.Increment(ref _activeScans);
            UpdateMaximum(active);
            try
            {
                var delay = _delaySelector(path);
                if (delay > 0)
                {
                    await Task.Delay(delay, cancellationToken);
                }

                return _resultSelector(path);
            }
            finally
            {
                Interlocked.Decrement(ref _activeScans);
            }
        }

        private void UpdateMaximum(int candidate)
        {
            var current = Volatile.Read(ref _maximumObservedConcurrency);
            while (candidate > current)
            {
                var previous = Interlocked.CompareExchange(
                    ref _maximumObservedConcurrency,
                    candidate,
                    current);
                if (previous == current)
                {
                    return;
                }

                current = previous;
            }
        }
    }
}
