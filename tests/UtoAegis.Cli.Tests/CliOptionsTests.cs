using UtoAegis.Cli;

namespace UtoAegis.Cli.Tests;

[TestClass]
public sealed class CliOptionsTests
{
    [TestMethod]
    public void TryParse_ScanWithSignatureFile_ReturnsExpectedOptions()
    {
        var parsed = CliOptions.TryParse(
            ["scan", "--signatures", "rules.jsonl", "--quiet", "sample.bin"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.Scan, options.Command);
        Assert.AreEqual("rules.jsonl", options.SignaturePath);
        Assert.AreEqual("sample.bin", options.InputPath);
        Assert.IsTrue(options.Quiet);
    }

    [TestMethod]
    public void TryParse_DuplicateSignatureOption_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["--signatures", "one.jsonl", "--signatures", "two.jsonl", "sample.bin"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--signatures may only be supplied once.", error);
    }

    [TestMethod]
    public void TryParse_ImportWithSignatureFile_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            [
                "import-hashes",
                "--database",
                "reputation.db",
                "--signatures",
                "rules.jsonl",
                "indicators.jsonl"
            ],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--signatures is only valid with scan or scan-directory.", error);
    }

    [TestMethod]
    public void TryParse_OptionTerminator_AllowsDashPrefixedInputPath()
    {
        var parsed = CliOptions.TryParse(
            ["scan", "--signatures", "rules.jsonl", "--", "--sample.bin"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual("--sample.bin", options.InputPath);
    }

    [TestMethod]
    public void TryParse_DirectoryOptions_ReturnExpectedValues()
    {
        var parsed = CliOptions.TryParse(
            [
                "scan-directory",
                "--recursive",
                "--max-concurrency",
                "8",
                "--signatures",
                "rules.jsonl",
                "samples"
            ],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.ScanDirectory, options.Command);
        Assert.AreEqual("samples", options.InputPath);
        Assert.AreEqual("rules.jsonl", options.SignaturePath);
        Assert.IsTrue(options.Recursive);
        Assert.AreEqual(8, options.MaximumConcurrency);
    }

    [TestMethod]
    public void TryParse_DirectoryDefaults_AreBounded()
    {
        var parsed = CliOptions.TryParse(
            ["scan-directory", "samples"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.IsFalse(options.Recursive);
        Assert.AreEqual(4, options.MaximumConcurrency);
    }

    [TestMethod]
    public void TryParse_RecursiveWithFileScan_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["scan", "--recursive", "sample.bin"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--recursive is only valid with scan-directory.", error);
    }

    [TestMethod]
    public void TryParse_ConcurrencyWithImport_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            [
                "import-hashes",
                "--database",
                "reputation.db",
                "--max-concurrency",
                "2",
                "indicators.jsonl"
            ],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--max-concurrency is only valid with scan-directory.", error);
    }

    [TestMethod]
    public void TryParse_ConcurrencyOutsideAllowedRange_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["scan-directory", "--max-concurrency", "33", "samples"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--max-concurrency requires an integer from 1 to 32.", error);
    }

    [TestMethod]
    public void TryParse_DuplicateRecursiveOption_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["scan-directory", "--recursive", "--recursive", "samples"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--recursive may only be supplied once.", error);
    }

    [TestMethod]
    public void TryParse_ScanWithHistory_ReturnsHistoryPath()
    {
        var parsed = CliOptions.TryParse(
            ["scan", "--history", "history.db", "sample.bin"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual("history.db", options.HistoryPath);
    }

    [TestMethod]
    public void TryParse_HistoryList_ReturnsBoundedLimit()
    {
        var parsed = CliOptions.TryParse(
            ["history", "list", "--history", "history.db", "--limit", "50"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.HistoryList, options.Command);
        Assert.AreEqual(50, options.HistoryLimit);
    }

    [TestMethod]
    public void TryParse_HistoryShow_RequiresCanonicalScanId()
    {
        var parsed = CliOptions.TryParse(
            ["history", "show", "--history", "history.db", "not-a-guid"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual(
            "history show requires a scan ID in canonical GUID format.",
            error);
    }

    [TestMethod]
    public void TryParse_HistoryPrune_RequiresRetentionAge()
    {
        var parsed = CliOptions.TryParse(
            ["history", "prune", "--history", "history.db"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual(
            "history prune requires --older-than-days <days>.",
            error);
    }

    [TestMethod]
    public void TryParse_ImportWithHistory_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            [
                "import-hashes",
                "--database",
                "reputation.db",
                "--history",
                "history.db",
                "indicators.jsonl"
            ],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual(
            "--history is only valid with scans or history commands.",
            error);
    }
}
