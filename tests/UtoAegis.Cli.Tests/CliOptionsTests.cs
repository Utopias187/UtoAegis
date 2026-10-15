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
        Assert.AreEqual("--signatures is only valid with the scan command.", error);
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
}
