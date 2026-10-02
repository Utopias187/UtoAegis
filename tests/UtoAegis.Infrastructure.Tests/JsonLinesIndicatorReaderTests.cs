using UtoAegis.Infrastructure.Importing;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class JsonLinesIndicatorReaderTests
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
    public async Task ReadAsync_ValidLines_DeduplicatesIdenticalIndicators()
    {
        var path = Path.Combine(_testDirectory, "valid.jsonl");
        var line =
            "{\"sha256\":\"" + new string('d', 64) +
            "\",\"source\":\"synthetic-test-feed\",\"malwareFamily\":\"Test.Family\"}";
        await File.WriteAllLinesAsync(path, [line, line]);
        var result = await JsonLinesIndicatorReader.ReadAsync(path);

        Assert.HasCount(1, result.Indicators);
        Assert.AreEqual(1, result.DuplicateCount);
    }

    [TestMethod]
    public async Task ReadAsync_ConflictingDuplicate_RejectsEntireFile()
    {
        var path = Path.Combine(_testDirectory, "conflict.jsonl");
        var hash = new string('e', 64);
        await File.WriteAllLinesAsync(
            path,
            [
                $"{{\"sha256\":\"{hash}\",\"source\":\"feed-one\"}}",
                $"{{\"sha256\":\"{hash}\",\"source\":\"feed-two\"}}"
            ]);
        var exception = await Assert.ThrowsExactlyAsync<IndicatorImportException>(
            async () => await JsonLinesIndicatorReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "conflicting metadata");
    }

    [TestMethod]
    public async Task ReadAsync_UnknownProperty_RejectsLine()
    {
        var path = Path.Combine(_testDirectory, "unknown-property.jsonl");
        await File.WriteAllTextAsync(
            path,
            "{\"sha256\":\"" + new string('f', 64) +
            "\",\"source\":\"test\",\"unexpected\":true}");
        var exception = await Assert.ThrowsExactlyAsync<IndicatorImportException>(
            async () => await JsonLinesIndicatorReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "line 1");
    }

    [TestMethod]
    public async Task ReadAsync_DuplicateProperty_RejectsLine()
    {
        var path = Path.Combine(_testDirectory, "duplicate-property.jsonl");
        await File.WriteAllTextAsync(
            path,
            "{\"sha256\":\"" + new string('a', 64) +
            "\",\"source\":\"feed-one\",\"source\":\"feed-two\"}");

        var exception = await Assert.ThrowsExactlyAsync<IndicatorImportException>(
            async () => await JsonLinesIndicatorReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "Duplicate JSON property");
    }
}
