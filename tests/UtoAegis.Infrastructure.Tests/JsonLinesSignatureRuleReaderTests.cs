using System.Text;
using UtoAegis.Infrastructure.Signatures;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class JsonLinesSignatureRuleReaderTests
{
    private const string ValidRule =
        "{\"id\":\"demo.marker\",\"name\":\"Harmless marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"55544f4145474953\"}";

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
    public async Task ReadAsync_ValidRules_ReturnsNormalizedRules()
    {
        var path = await WriteTextAsync(
            "rules.jsonl",
            ValidRule + Environment.NewLine +
            "{\"id\":\"demo.second\",\"name\":\"Second marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"4142434445464748\"}");

        var result = await JsonLinesSignatureRuleReader.ReadAsync(path);

        Assert.HasCount(2, result.Rules);
        Assert.AreEqual(0, result.DuplicateCount);
        Assert.AreEqual("55544f4145474953", result.Rules[0].HexPattern);
    }

    [TestMethod]
    public async Task ReadAsync_IdenticalDuplicateRule_CountsAndIgnoresDuplicate()
    {
        var path = await WriteTextAsync(
            "duplicates.jsonl",
            ValidRule + Environment.NewLine +
            "{\"id\":\"DEMO.MARKER\",\"name\":\"Harmless marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"55544F4145474953\"}");

        var result = await JsonLinesSignatureRuleReader.ReadAsync(path);

        Assert.HasCount(1, result.Rules);
        Assert.AreEqual(1, result.DuplicateCount);
    }

    [TestMethod]
    public async Task ReadAsync_ConflictingDuplicateRule_RejectsFile()
    {
        var path = await WriteTextAsync(
            "conflict.jsonl",
            ValidRule + Environment.NewLine +
            "{\"id\":\"demo.marker\",\"name\":\"Different marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"4142434445464748\"}");

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "conflicting definitions");
    }

    [TestMethod]
    public async Task ReadAsync_UnknownProperty_RejectsFile()
    {
        var path = await WriteTextAsync(
            "unknown-property.jsonl",
            "{\"id\":\"demo.marker\",\"name\":\"Harmless marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"55544f4145474953\",\"unexpected\":true}");

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "not a valid signature rule");
    }

    [TestMethod]
    public async Task ReadAsync_DuplicateJsonProperty_RejectsFile()
    {
        var path = await WriteTextAsync(
            "duplicate-property.jsonl",
            "{\"id\":\"demo.marker\",\"id\":\"demo.other\",\"name\":\"Harmless marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"55544f4145474953\"}");

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "Duplicate JSON property");
    }

    [TestMethod]
    public async Task ReadAsync_InvalidPattern_RejectsFile()
    {
        var path = await WriteTextAsync(
            "invalid-pattern.jsonl",
            "{\"id\":\"demo.marker\",\"name\":\"Harmless marker\",\"source\":\"test-fixtures\",\"hexPattern\":\"not-hex\"}");

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "Hex pattern");
    }

    [TestMethod]
    public async Task ReadAsync_EmptyFile_RejectsFile()
    {
        var path = await WriteTextAsync("empty.jsonl", string.Empty);

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "at least one valid rule");
    }

    [TestMethod]
    public async Task ReadAsync_InvalidUtf8_RejectsFile()
    {
        var path = Path.Combine(_testDirectory, "invalid-utf8.jsonl");
        await File.WriteAllBytesAsync(path, [0xC3, 0x28]);

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "could not be read");
    }

    [TestMethod]
    public async Task ReadAsync_TooManyRules_RejectsFile()
    {
        var lines = Enumerable.Range(0, JsonLinesSignatureRuleReader.MaximumRuleCount + 1)
            .Select(index =>
                $"{{\"id\":\"demo.rule-{index}\",\"name\":\"Rule {index}\",\"source\":\"test-fixtures\",\"hexPattern\":\"55544f4145474953\"}}");
        var path = await WriteTextAsync("too-many.jsonl", string.Join(Environment.NewLine, lines));

        var exception = await Assert.ThrowsExactlyAsync<SignatureRuleFileException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path));

        StringAssert.Contains(exception.Message, "rule limit");
    }

    [TestMethod]
    public async Task ReadAsync_PreCancelledToken_ThrowsCancellation()
    {
        var path = await WriteTextAsync("cancelled.jsonl", ValidRule);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await JsonLinesSignatureRuleReader.ReadAsync(path, cancellation.Token));
    }

    private async Task<string> WriteTextAsync(string fileName, string content)
    {
        var path = Path.Combine(_testDirectory, fileName);
        await File.WriteAllTextAsync(path, content, new UTF8Encoding(false));
        return path;
    }
}
