using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.History;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;
using UtoAegis.Infrastructure.History;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SqliteScanHistoryStoreTests
{
    private string _testDirectory = null!;
    private string _databasePath = null!;

    [TestInitialize]
    public void CreateTestDirectory()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        _databasePath = Path.Combine(_testDirectory, "history.db");
    }

    [TestCleanup]
    public void DeleteTestDirectory()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task InitializeAsync_NewDatabase_CreatesCurrentSchema()
    {
        var store = new SqliteScanHistoryStore(_databasePath);

        await store.InitializeAsync();

        Assert.IsTrue(File.Exists(_databasePath));
        await using var connection = new SqliteConnection($"Data Source={_databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var version = (long)(await command.ExecuteScalarAsync())!;
        Assert.AreEqual(SqliteScanHistoryStore.CurrentSchemaVersion, version);
    }

    [TestMethod]
    public async Task AppendAndGetAsync_RichRecord_PreservesStructuredDetails()
    {
        var store = new SqliteScanHistoryStore(_databasePath);
        await store.InitializeAsync();
        var expected = CreateRecord(
            Guid.Parse("7c920ecb-49ff-465b-a796-4481625367f2"),
            ParseTime("2026-10-15T12:00:00Z"));

        await store.AppendAsync(expected);
        var actual = await store.GetAsync(expected.Id);

        Assert.IsNotNull(actual);
        Assert.AreEqual(expected.Id, actual.Id);
        Assert.AreEqual(expected.TargetPath, actual.TargetPath);
        Assert.AreEqual(expected.Outcome, actual.Outcome);
        Assert.AreEqual(1, actual.Files.Count);
        Assert.AreEqual(expected.Files[0].Sha256, actual.Files[0].Sha256);
        Assert.AreEqual("Harmless.Test", actual.Files[0].ReputationMalwareFamily);
        Assert.AreEqual(1, actual.Files[0].SignatureMatches.Count);
        Assert.AreEqual("demo.rule", actual.Files[0].SignatureMatches[0].RuleId);
        Assert.AreEqual(1, actual.Issues.Count);
        Assert.AreEqual(DirectoryScanIssueKind.ReparsePointSkipped, actual.Issues[0].Kind);
    }

    [TestMethod]
    public async Task ListAsync_ReturnsNewestFirstAndHonorsLimit()
    {
        var store = new SqliteScanHistoryStore(_databasePath);
        await store.InitializeAsync();
        var older = CreateRecord(Guid.NewGuid(), ParseTime("2026-10-14T12:00:00Z"));
        var newer = CreateRecord(Guid.NewGuid(), ParseTime("2026-10-15T12:00:00Z"));
        await store.AppendAsync(older);
        await store.AppendAsync(newer);

        var summaries = await store.ListAsync(1);

        Assert.HasCount(1, summaries);
        Assert.AreEqual(newer.Id, summaries[0].Id);
        Assert.AreEqual(1, summaries[0].FileCount);
        Assert.AreEqual(1, summaries[0].DetectedFileCount);
        Assert.AreEqual(1, summaries[0].IssueCount);
    }

    [TestMethod]
    public async Task GetAsync_AbsentId_ReturnsNull()
    {
        var store = new SqliteScanHistoryStore(_databasePath);
        await store.InitializeAsync();

        var result = await store.GetAsync(Guid.NewGuid());

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task PruneAsync_DeletesOnlyRecordsOlderThanCutoffAndCascades()
    {
        var store = new SqliteScanHistoryStore(_databasePath);
        await store.InitializeAsync();
        var older = CreateRecord(Guid.NewGuid(), ParseTime("2026-10-13T12:00:00Z"));
        var boundary = CreateRecord(Guid.NewGuid(), ParseTime("2026-10-14T12:00:00Z"));
        await store.AppendAsync(older);
        await store.AppendAsync(boundary);

        var result = await store.PruneAsync(ParseTime("2026-10-14T12:00:01Z"));

        Assert.AreEqual(1, result.DeletedScanCount);
        Assert.IsNull(await store.GetAsync(older.Id));
        Assert.IsNotNull(await store.GetAsync(boundary.Id));
        await using var connection = new SqliteConnection($"Data Source={_databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM scan_history_signature_matches;";
        Assert.AreEqual(1L, await command.ExecuteScalarAsync());
    }

    [TestMethod]
    public async Task AppendAsync_ChildInsertFails_RollsBackCompleteRecord()
    {
        var store = new SqliteScanHistoryStore(_databasePath);
        await store.InitializeAsync();
        await using (var connection = new SqliteConnection($"Data Source={_databasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                CREATE TRIGGER reject_test_match
                BEFORE INSERT ON scan_history_signature_matches
                BEGIN
                    SELECT RAISE(ABORT, 'synthetic history failure');
                END;
                """;
            await command.ExecuteNonQueryAsync();
        }

        var record = CreateRecord(Guid.NewGuid(), ParseTime("2026-10-15T12:00:00Z"));
        await Assert.ThrowsExactlyAsync<ScanHistoryStoreException>(
            async () => await store.AppendAsync(record));

        Assert.IsNull(await store.GetAsync(record.Id));
    }

    [TestMethod]
    public async Task InitializeAsync_NewerSchema_RejectsDatabase()
    {
        Directory.CreateDirectory(_testDirectory);
        await using (var connection = new SqliteConnection($"Data Source={_databasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version = 999;";
            await command.ExecuteNonQueryAsync();
        }

        var store = new SqliteScanHistoryStore(_databasePath);

        var exception = await Assert.ThrowsExactlyAsync<ScanHistoryStoreException>(
            async () => await store.InitializeAsync());
        StringAssert.Contains(exception.Message, "newer than supported");
    }

    [TestMethod]
    public async Task ListAsync_InvalidLimit_Throws()
    {
        var store = new SqliteScanHistoryStore(_databasePath);

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await store.ListAsync(SqliteScanHistoryStore.MaximumListLimit + 1));
    }

    private static ScanHistoryRecord CreateRecord(Guid id, DateTimeOffset startedUtc)
    {
        var files = new[]
        {
            new ScanHistoryFile(
                "sample.bin",
                FileHashScanStatus.Success,
                new string('a', 64),
                42,
                Detected: true,
                Completed: true,
                HashReputationStatus.Malicious,
                ThreatClassification.Malware,
                "Harmless.Test",
                "unit-test",
                ParseTime("2026-01-02T03:04:05Z"),
                SignatureScanStatus.Detected,
                "fixed-byte-v1",
                [new ScanHistorySignatureMatch("demo.rule", "Demo rule", "unit-test", 7, 8)],
                HashError: null,
                ReputationError: null,
                SignatureError: null)
        };
        var issues = new[]
        {
            new ScanHistoryIssue(
                "skipped-link",
                DirectoryScanIssueKind.ReparsePointSkipped,
                "Reparse point skipped.")
        };

        return ScanHistoryRecord.Restore(
            id,
            ScanHistoryTargetKind.Directory,
            "root",
            recursive: true,
            startedUtc,
            startedUtc.AddSeconds(2),
            ScanHistoryOutcome.Partial,
            files,
            issues,
            errorMessage: null);
    }

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
}
