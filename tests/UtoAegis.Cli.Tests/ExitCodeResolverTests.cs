using UtoAegis.Cli;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Cli.Tests;

[TestClass]
public sealed class ExitCodeResolverTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void ForDirectory_CompletedWithoutDetection_ReturnsSuccess()
    {
        var result = FinishedDirectory(SuccessfulFile(detected: false), issues: []);

        Assert.AreEqual(ExitCodes.Success, ExitCodeResolver.ForDirectory(result));
    }

    [TestMethod]
    public void ForDirectory_CompletedWithDetection_ReturnsThreatDetected()
    {
        var result = FinishedDirectory(SuccessfulFile(detected: true), issues: []);

        Assert.AreEqual(ExitCodes.ThreatDetected, ExitCodeResolver.ForDirectory(result));
    }

    [TestMethod]
    public void ForDirectory_PartialWithoutDetection_ReturnsPartial()
    {
        var result = FinishedDirectory(SuccessfulFile(detected: false), [TraversalIssue()]);

        Assert.AreEqual(ExitCodes.DirectoryScanPartial, ExitCodeResolver.ForDirectory(result));
    }

    [TestMethod]
    public void ForDirectory_PartialWithDetection_ReturnsCombinedCode()
    {
        var result = FinishedDirectory(SuccessfulFile(detected: true), [TraversalIssue()]);

        Assert.AreEqual(
            ExitCodes.ThreatDetectedWithPartialResults,
            ExitCodeResolver.ForDirectory(result));
    }

    [TestMethod]
    public void ForDirectory_RootFailure_ReturnsDirectoryFailure()
    {
        var result = DirectoryScanResult.Failure(
            DirectoryScanStatus.DirectoryNotFound,
            "missing",
            [],
            TimeSpan.Zero,
            "missing");

        Assert.AreEqual(ExitCodes.DirectoryScanFailed, ExitCodeResolver.ForDirectory(result));
    }

    [TestMethod]
    public void ForHistoryWriteFailure_WithDetection_PreservesDetectionSignal()
    {
        Assert.AreEqual(
            ExitCodes.ThreatDetectedWithHistoryFailure,
            ExitCodeResolver.ForHistoryWriteFailure(detected: true));
    }

    [TestMethod]
    public void ForHistoryWriteFailure_WithoutDetection_ReturnsHistoryFailure()
    {
        Assert.AreEqual(
            ExitCodes.HistoryStoreFailed,
            ExitCodeResolver.ForHistoryWriteFailure(detected: false));
    }

    [TestMethod]
    public void ForOperationFailure_Monitor_ReturnsMonitorFailure()
    {
        Assert.AreEqual(
            ExitCodes.MonitorFailed,
            ExitCodeResolver.ForOperationFailure(CliCommand.Monitor));
    }

    private static DirectoryScanResult FinishedDirectory(
        FileScanResult file,
        IReadOnlyList<DirectoryScanIssue> issues) =>
        DirectoryScanResult.Finished(
            "root",
            [new DirectoryFileScanResult("sample.bin", file)],
            issues,
            TimeSpan.Zero);

    private static FileScanResult SuccessfulFile(bool detected)
    {
        var signatures = SignatureScanResult.Completed(
            "stub",
            "sample.bin",
            detected
                ? [new SignatureMatch("demo.rule", "Demo", "test", 0, 8)]
                : [],
            8,
            TimeSpan.Zero);
        return new FileScanResult(
            FileHashScanResult.Success("sample.bin", Hash, 8, TimeSpan.Zero),
            Reputation: null,
            Signatures: signatures);
    }

    private static DirectoryScanIssue TraversalIssue() =>
        new(
            "skipped",
            DirectoryScanIssueKind.ReparsePointSkipped,
            "skipped");
}
