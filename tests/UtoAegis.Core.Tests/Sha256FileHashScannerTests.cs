using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class Sha256FileHashScannerTests
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
    public async Task ScanAsync_KnownContent_ReturnsExpectedSha256()
    {
        var path = Path.Combine(_testDirectory, "known.txt");
        await File.WriteAllTextAsync(path, "abc");
        var scanner = new Sha256FileHashScanner();

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(FileHashScanStatus.Success, result.Status);
        Assert.AreEqual(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            result.Sha256);
        Assert.AreEqual(3L, result.FileSizeBytes);
        Assert.IsNull(result.ErrorMessage);
        Assert.IsTrue(Path.IsPathFullyQualified(result.Path!));
    }

    [TestMethod]
    public async Task ScanAsync_EmptyFile_ReturnsExpectedSha256()
    {
        var path = Path.Combine(_testDirectory, "empty.bin");
        await File.WriteAllBytesAsync(path, []);
        var scanner = new Sha256FileHashScanner();

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(FileHashScanStatus.Success, result.Status);
        Assert.AreEqual(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            result.Sha256);
        Assert.AreEqual(0L, result.FileSizeBytes);
    }

    [TestMethod]
    public async Task ScanAsync_MissingFile_ReturnsFileNotFound()
    {
        var path = Path.Combine(_testDirectory, "missing.exe");
        var scanner = new Sha256FileHashScanner();

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(FileHashScanStatus.FileNotFound, result.Status);
        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Sha256);
    }

    [TestMethod]
    public async Task ScanAsync_Directory_ReturnsNotAFile()
    {
        var scanner = new Sha256FileHashScanner();
        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(FileHashScanStatus.NotAFile, result.Status);
        Assert.IsNull(result.Sha256);
    }

    [TestMethod]
    public async Task ScanAsync_WhitespacePath_ReturnsInvalidPath()
    {
        var scanner = new Sha256FileHashScanner();
        var result = await scanner.ScanAsync("   ");

        Assert.AreEqual(FileHashScanStatus.InvalidPath, result.Status);
        Assert.IsNull(result.Path);
    }

    [TestMethod]
    public async Task ScanAsync_FileLockedByAnotherHandle_ReturnsIoError()
    {
        var path = Path.Combine(_testDirectory, "locked.bin");
        await File.WriteAllTextAsync(path, "safe test content");
        await using var exclusiveHandle = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);
        var scanner = new Sha256FileHashScanner();

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(FileHashScanStatus.IoError, result.Status);
        Assert.IsNull(result.Sha256);
    }

    [TestMethod]
    public async Task ScanAsync_PreCancelledToken_ThrowsCancellation()
    {
        var path = Path.Combine(_testDirectory, "cancelled.txt");
        await File.WriteAllTextAsync(path, "safe test content");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var scanner = new Sha256FileHashScanner();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await scanner.ScanAsync(path, cancellation.Token));
    }

    [TestMethod]
    public void Constructor_BufferSmallerThanFourKiB_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new Sha256FileHashScanner(4095));
    }
}
