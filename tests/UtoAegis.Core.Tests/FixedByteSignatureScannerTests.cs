using System.Text;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class FixedByteSignatureScannerTests
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
    public async Task ScanAsync_MatchingFile_ReturnsDetectionEvidence()
    {
        var path = Path.Combine(_testDirectory, "matching.bin");
        await File.WriteAllBytesAsync(path, Encoding.ASCII.GetBytes("prefix-UTOAEGIS-suffix"));
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.Detected, result.Status);
        Assert.IsTrue(result.IsCompleted);
        Assert.IsTrue(result.IsDetected);
        Assert.AreEqual(FixedByteSignatureScanner.Engine, result.EngineName);
        Assert.AreEqual(1, result.Matches.Count);
        Assert.AreEqual("demo.marker", result.Matches[0].RuleId);
        Assert.AreEqual(7L, result.Matches[0].Offset);
        Assert.AreEqual(8, result.Matches[0].PatternLengthBytes);
        Assert.AreEqual(22L, result.FileSizeBytes);
        Assert.IsNull(result.ErrorMessage);
    }

    [TestMethod]
    public async Task ScanAsync_NoMatchingPattern_ReturnsNoMatch()
    {
        var path = Path.Combine(_testDirectory, "unknown.bin");
        await File.WriteAllTextAsync(path, "harmless test content");
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.NoMatch, result.Status);
        Assert.IsTrue(result.IsCompleted);
        Assert.IsFalse(result.IsDetected);
        Assert.IsEmpty(result.Matches);
        Assert.AreEqual(new FileInfo(path).Length, result.FileSizeBytes);
    }

    [TestMethod]
    public async Task ScanAsync_PatternCrossingBufferBoundary_ReturnsCorrectOffset()
    {
        const int prefixLength = 4092;
        var pattern = Encoding.ASCII.GetBytes("UTOAEGIS");
        var content = new byte[prefixLength + pattern.Length + 32];
        Array.Fill(content, (byte)'x');
        pattern.CopyTo(content, prefixLength);
        var path = Path.Combine(_testDirectory, "boundary.bin");
        await File.WriteAllBytesAsync(path, content);
        var scanner = new FixedByteSignatureScanner(
            [CreateRule("demo.boundary", "UTOAEGIS")],
            bufferSize: 4096);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.Detected, result.Status);
        Assert.AreEqual(prefixLength, result.Matches[0].Offset);
    }

    [TestMethod]
    public async Task ScanAsync_MultipleRules_ReturnsFirstMatchPerRuleOrderedByOffset()
    {
        var path = Path.Combine(_testDirectory, "multiple.bin");
        await File.WriteAllTextAsync(path, "SECOND--FIRST---SECOND");
        var scanner = new FixedByteSignatureScanner(
        [
            CreateRule("demo.first", "FIRST---"),
            CreateRule("demo.second", "SECOND--")
        ]);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.Detected, result.Status);
        Assert.HasCount(2, result.Matches);
        Assert.AreEqual("demo.second", result.Matches[0].RuleId);
        Assert.AreEqual(0L, result.Matches[0].Offset);
        Assert.AreEqual("demo.first", result.Matches[1].RuleId);
        Assert.AreEqual(8L, result.Matches[1].Offset);
    }

    [TestMethod]
    public async Task ScanAsync_EmptyFile_ReturnsNoMatch()
    {
        var path = Path.Combine(_testDirectory, "empty.bin");
        await File.WriteAllBytesAsync(path, []);
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.NoMatch, result.Status);
        Assert.AreEqual(0L, result.FileSizeBytes);
    }

    [TestMethod]
    public async Task ScanAsync_MissingFile_ReturnsFileNotFound()
    {
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(Path.Combine(_testDirectory, "missing.bin"));

        Assert.AreEqual(SignatureScanStatus.FileNotFound, result.Status);
        Assert.IsFalse(result.IsCompleted);
        Assert.IsEmpty(result.Matches);
    }

    [TestMethod]
    public async Task ScanAsync_Directory_ReturnsNotAFile()
    {
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(_testDirectory);

        Assert.AreEqual(SignatureScanStatus.NotAFile, result.Status);
    }

    [TestMethod]
    public async Task ScanAsync_PreCancelledToken_ThrowsCancellation()
    {
        var path = Path.Combine(_testDirectory, "cancelled.bin");
        await File.WriteAllTextAsync(path, "harmless test content");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await scanner.ScanAsync(path, cancellation.Token));
    }

    [TestMethod]
    public async Task ScanAsync_FileLockedByAnotherHandle_ReturnsIoError()
    {
        var path = Path.Combine(_testDirectory, "locked.bin");
        await File.WriteAllTextAsync(path, "harmless test content");
        await using var exclusiveHandle = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);
        var scanner = new FixedByteSignatureScanner([CreateRule("demo.marker", "UTOAEGIS")]);

        var result = await scanner.ScanAsync(path);

        Assert.AreEqual(SignatureScanStatus.IoError, result.Status);
    }

    [TestMethod]
    public void Constructor_DuplicateRuleIds_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new FixedByteSignatureScanner(
        [
            CreateRule("demo.marker", "UTOAEGIS"),
            CreateRule("DEMO.MARKER", "DIFFERENT")
        ]));
    }

    [TestMethod]
    public void Constructor_EmptyRules_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new FixedByteSignatureScanner([]));
    }

    [TestMethod]
    public void Constructor_BufferSmallerThanFourKiB_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new FixedByteSignatureScanner(
                [CreateRule("demo.marker", "UTOAEGIS")],
                bufferSize: 4095));
    }

    private static ByteSignatureRule CreateRule(string id, string asciiPattern)
    {
        var created = ByteSignatureRule.TryCreate(
            id,
            $"Rule {id}",
            "test-fixtures",
            Convert.ToHexString(Encoding.ASCII.GetBytes(asciiPattern)),
            out var rule,
            out var error);

        Assert.IsTrue(created, error);
        return rule!;
    }
}
