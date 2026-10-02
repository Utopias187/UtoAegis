using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Reputation;
using UtoAegis.Infrastructure.Reputation;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SqliteHashReputationStoreTests
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
        _databasePath = Path.Combine(_testDirectory, "reputation.db");
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
        var store = new SqliteHashReputationStore(_databasePath);

        await store.InitializeAsync();

        Assert.IsTrue(File.Exists(_databasePath));
        await using var connection = new SqliteConnection($"Data Source={_databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var version = (long)(await command.ExecuteScalarAsync())!;
        Assert.AreEqual(SqliteHashReputationStore.CurrentSchemaVersion, version);
    }

    [TestMethod]
    public async Task LookupAsync_AbsentDigest_ReturnsUnknown()
    {
        var store = new SqliteHashReputationStore(_databasePath);
        await store.InitializeAsync();

        var result = await store.LookupAsync(new string('a', 64));

        Assert.AreEqual(HashReputationStatus.Unknown, result.Status);
        Assert.IsNull(result.Indicator);
    }

    [TestMethod]
    public async Task ImportAsync_NewIndicator_CanBeLookedUp()
    {
        var store = new SqliteHashReputationStore(_databasePath);
        await store.InitializeAsync();
        var indicator = CreateIndicator('b');

        var import = await store.ImportAsync([indicator]);
        var lookup = await store.LookupAsync(indicator.Sha256.ToUpperInvariant());

        Assert.AreEqual(1, import.ProcessedCount);
        Assert.AreEqual(1, import.ChangedCount);
        Assert.AreEqual(HashReputationStatus.Malicious, lookup.Status);
        Assert.AreEqual(indicator, lookup.Indicator);
        Assert.IsNotNull(lookup.RecordUpdatedUtc);
    }

    [TestMethod]
    public async Task ImportAsync_IdenticalIndicator_IsIdempotent()
    {
        var store = new SqliteHashReputationStore(_databasePath);
        await store.InitializeAsync();
        var indicator = CreateIndicator('c');

        await store.ImportAsync([indicator]);
        var secondImport = await store.ImportAsync([indicator]);

        Assert.AreEqual(1, secondImport.ProcessedCount);
        Assert.AreEqual(0, secondImport.ChangedCount);
        Assert.AreEqual(1, secondImport.UnchangedCount);
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

        var store = new SqliteHashReputationStore(_databasePath);

        var exception = await Assert.ThrowsExactlyAsync<ReputationStoreException>(
            async () => await store.InitializeAsync());
        StringAssert.Contains(exception.Message, "newer than supported");
    }

    [TestMethod]
    public async Task LookupAsync_InvalidDigest_ThrowsArgumentException()
    {
        var store = new SqliteHashReputationStore(_databasePath);

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await store.LookupAsync("invalid"));
    }

    [TestMethod]
    public async Task LookupAsync_CorruptedDatabase_ReturnsLookupFailed()
    {
        Directory.CreateDirectory(_testDirectory);
        await File.WriteAllBytesAsync(_databasePath, [0x55, 0x74, 0x6f, 0x41, 0x65, 0x67, 0x69, 0x73]);
        var store = new SqliteHashReputationStore(_databasePath);

        var result = await store.LookupAsync(new string('a', 64));

        Assert.AreEqual(HashReputationStatus.LookupFailed, result.Status);
        Assert.IsNull(result.Indicator);
    }

    [TestMethod]
    public async Task ImportAsync_SecondInsertFails_RollsBackFirstInsert()
    {
        var store = new SqliteHashReputationStore(_databasePath);
        await store.InitializeAsync();
        var first = CreateIndicator('1');
        var rejected = CreateIndicator('2');

        await using (var connection = new SqliteConnection($"Data Source={_databasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                $"""
                CREATE TRIGGER reject_test_hash
                BEFORE INSERT ON malicious_hashes
                WHEN NEW.sha256 = '{rejected.Sha256}'
                BEGIN
                    SELECT RAISE(ABORT, 'synthetic transaction failure');
                END;
                """;
            await command.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsExactlyAsync<ReputationStoreException>(
            async () => await store.ImportAsync([first, rejected]));
        var firstLookup = await store.LookupAsync(first.Sha256);

        Assert.AreEqual(HashReputationStatus.Unknown, firstLookup.Status);
    }

    private static MalwareHashIndicator CreateIndicator(char hashCharacter)
    {
        var created = MalwareHashIndicator.TryCreate(
            new string(hashCharacter, 64),
            ThreatClassification.Malware,
            "synthetic-test-feed",
            "Harmless.Test.Family",
            DateTimeOffset.Parse("2026-01-02T03:04:05Z", CultureInfo.InvariantCulture),
            out var indicator,
            out var error);

        Assert.IsTrue(created, error);
        return indicator!;
    }
}
