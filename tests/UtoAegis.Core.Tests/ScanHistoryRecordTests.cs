using System.Globalization;
using UtoAegis.Core.History;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class ScanHistoryRecordTests
{
    [TestMethod]
    public void FromFileScan_Success_ProducesCompletedSummary()
    {
        var start = DateTimeOffset.Parse(
            "2026-10-15T12:00:00Z",
            CultureInfo.InvariantCulture);
        var result = new FileScanResult(
            FileHashScanResult.Success("sample.bin", new string('a', 64), 42, TimeSpan.Zero),
            Reputation: null,
            Signatures: null);

        var record = ScanHistoryRecord.FromFileScan(
            Guid.Parse("2af8af2f-aeab-48a2-981a-2f934d51704b"),
            "sample.bin",
            start,
            start.AddSeconds(1),
            result);

        Assert.AreEqual(ScanHistoryOutcome.Completed, record.Outcome);
        Assert.AreEqual(ScanHistoryTargetKind.File, record.TargetKind);
        Assert.AreEqual(1, record.Files.Count);
        Assert.AreEqual(0, record.DetectedFileCount);
        Assert.AreEqual(0, record.FailedFileCount);
    }

    [TestMethod]
    public void FromDirectoryScan_Partial_PreservesIssues()
    {
        var start = DateTimeOffset.Parse(
            "2026-10-15T12:00:00Z",
            CultureInfo.InvariantCulture);
        var fileResult = new FileScanResult(
            FileHashScanResult.Success("sample.bin", new string('b', 64), 10, TimeSpan.Zero),
            Reputation: null,
            Signatures: null);
        var directoryResult = DirectoryScanResult.Finished(
            "root",
            [new DirectoryFileScanResult("sample.bin", fileResult)],
            [new DirectoryScanIssue("link", DirectoryScanIssueKind.ReparsePointSkipped, "Skipped.")],
            TimeSpan.FromSeconds(1));

        var record = ScanHistoryRecord.FromDirectoryScan(
            Guid.Parse("71827c34-0d8e-474b-93b7-dd9f9d4f7a16"),
            "root",
            recursive: true,
            start,
            start.AddSeconds(1),
            directoryResult);

        Assert.AreEqual(ScanHistoryOutcome.Partial, record.Outcome);
        Assert.IsTrue(record.Recursive);
        Assert.AreEqual(1, record.Issues.Count);
        Assert.AreEqual(DirectoryScanIssueKind.ReparsePointSkipped, record.Issues[0].Kind);
    }

    [TestMethod]
    public void FromFileScan_InvalidTimeline_Throws()
    {
        var start = DateTimeOffset.Parse(
            "2026-10-15T12:00:00Z",
            CultureInfo.InvariantCulture);
        var result = new FileScanResult(
            FileHashScanResult.Success("sample.bin", new string('c', 64), 10, TimeSpan.Zero),
            Reputation: null,
            Signatures: null);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            ScanHistoryRecord.FromFileScan(
                Guid.NewGuid(),
                "sample.bin",
                start,
                start.AddSeconds(-1),
                result));
    }
}
