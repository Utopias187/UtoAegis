using UtoAegis.Cli;

namespace UtoAegis.Cli.Tests;

[TestClass]
public sealed class CliOptionsTests
{
    [TestMethod]
    public void TryParse_UpdateApply_ReturnsStoreBundleAndKeys()
    {
        var parsed = CliOptions.TryParse(
            [
                "updates", "apply", "--store", "content", "--trusted-key",
                "release-1=release-1.pem", "bundle"
            ],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.UpdateApply, options.Command);
        Assert.AreEqual("content", options.ContentStorePath);
        Assert.AreEqual("bundle", options.InputPath);
        Assert.HasCount(1, options.TrustedKeySpecs);
        Assert.AreEqual("release-1=release-1.pem", options.TrustedKeySpecs[0]);
    }

    [TestMethod]
    public void TryParse_UpdateStatus_DoesNotRequireKey()
    {
        var parsed = CliOptions.TryParse(
            ["updates", "status", "--store", "content", "--json"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.AreEqual(CliCommand.UpdateStatus, options!.Command);
        Assert.IsTrue(options.Json);
    }

    [TestMethod]
    public void TryParse_UpdateRollbackWithoutKey_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["updates", "rollback", "--store", "content"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        StringAssert.Contains(error, "require at least one --trusted-key");
    }

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
        Assert.AreEqual(
            "--signatures is only valid with scan, scan-directory, monitor, or quarantine add.",
            error);
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
        Assert.AreEqual("--recursive is only valid with scan-directory or monitor.", error);
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
        Assert.AreEqual(
            "--max-concurrency is only valid with scan-directory or monitor.",
            error);
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
    public void TryParse_MonitorOptions_ReturnExpectedValues()
    {
        var parsed = CliOptions.TryParse(
            [
                "monitor",
                "--recursive",
                "--max-concurrency",
                "8",
                "--debounce-ms",
                "250",
                "--queue-capacity",
                "128",
                "--history",
                "history.db",
                "samples"
            ],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.Monitor, options.Command);
        Assert.AreEqual("samples", options.InputPath);
        Assert.AreEqual("history.db", options.HistoryPath);
        Assert.IsTrue(options.Recursive);
        Assert.AreEqual(8, options.MaximumConcurrency);
        Assert.AreEqual(250, options.DebounceMilliseconds);
        Assert.AreEqual(128, options.MonitorQueueCapacity);
    }

    [TestMethod]
    public void TryParse_MonitorDefaults_AreBounded()
    {
        var parsed = CliOptions.TryParse(
            ["monitor", "samples"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliOptions.DefaultDebounceMilliseconds, options.DebounceMilliseconds);
        Assert.AreEqual(CliOptions.DefaultMonitorQueueCapacity, options.MonitorQueueCapacity);
    }

    [TestMethod]
    public void TryParse_DebounceOutsideAllowedRange_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["monitor", "--debounce-ms", "60001", "samples"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--debounce-ms requires an integer from 0 to 60000.", error);
    }

    [TestMethod]
    public void TryParse_QueueCapacityOutsideAllowedRange_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["monitor", "--queue-capacity", "0", "samples"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--queue-capacity requires an integer from 1 to 65536.", error);
    }

    [TestMethod]
    public void TryParse_DebounceWithScan_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["scan", "--debounce-ms", "250", "sample.bin"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("--debounce-ms is only valid with monitor.", error);
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
            "--history is only valid with scans, quarantine add, or history commands.",
            error);
    }

    [TestMethod]
    public void TryParse_QuarantineAdd_ReturnsDetectorAndVaultOptions()
    {
        var parsed = CliOptions.TryParse(
            [
                "quarantine", "add", "--vault", "vault", "--signatures", "rules.jsonl",
                "--history", "history.db", "sample.bin"
            ],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.QuarantineAdd, options.Command);
        Assert.AreEqual("vault", options.VaultPath);
        Assert.AreEqual("rules.jsonl", options.SignaturePath);
        Assert.AreEqual("history.db", options.HistoryPath);
        Assert.AreEqual("sample.bin", options.InputPath);
    }

    [TestMethod]
    public void TryParse_QuarantineAddWithoutDetector_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["quarantine", "add", "--vault", "vault", "sample.bin"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual(
            "quarantine add requires --database, --signatures, or both.",
            error);
    }

    [TestMethod]
    public void TryParse_QuarantineList_ReturnsLimit()
    {
        var parsed = CliOptions.TryParse(
            ["quarantine", "list", "--vault", "vault", "--limit", "10"],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.QuarantineList, options.Command);
        Assert.AreEqual(10, options.HistoryLimit);
    }

    [TestMethod]
    public void TryParse_QuarantineRestore_ReturnsDestination()
    {
        var id = Guid.NewGuid().ToString("D");
        var parsed = CliOptions.TryParse(
            [
                "quarantine", "restore", "--vault", "vault", "--destination",
                "restored.bin", id
            ],
            out var options,
            out var error);

        Assert.IsTrue(parsed);
        Assert.IsNull(error);
        Assert.IsNotNull(options);
        Assert.AreEqual(CliCommand.QuarantineRestore, options.Command);
        Assert.AreEqual("restored.bin", options.DestinationPath);
        Assert.AreEqual(id, options.InputPath);
    }

    [TestMethod]
    public void TryParse_QuarantineCommandWithoutVault_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["quarantine", "list"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual("Quarantine commands require --vault <path>.", error);
    }

    [TestMethod]
    public void TryParse_QuarantineManagementWithScanOptions_IsRejected()
    {
        var parsed = CliOptions.TryParse(
            ["quarantine", "list", "--vault", "vault", "--database", "reputation.db"],
            out var options,
            out var error);

        Assert.IsFalse(parsed);
        Assert.IsNull(options);
        Assert.AreEqual(
            "Scan database, signature, and history options are not valid with quarantine management commands.",
            error);
    }
}
