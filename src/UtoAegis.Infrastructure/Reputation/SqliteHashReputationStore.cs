using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Reputation;

namespace UtoAegis.Infrastructure.Reputation;

public sealed class SqliteHashReputationStore : IHashReputationStore
{
    public const int CurrentSchemaVersion = 1;

    private readonly string _databasePath;

    public SqliteHashReputationStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _databasePath = Path.GetFullPath(databasePath);
    }

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var directory = Path.GetDirectoryName(_databasePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await using var connection = CreateConnection(SqliteOpenMode.ReadWriteCreate);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            await ExecuteNonQueryAsync(
                    connection,
                    "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;",
                    transaction: null,
                    cancellationToken)
                .ConfigureAwait(false);

            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);

            var version = await ReadSchemaVersionAsync(connection, transaction, cancellationToken)
                .ConfigureAwait(false);

            if (version > CurrentSchemaVersion)
            {
                throw new ReputationStoreException(
                    $"Database schema version {version} is newer than supported version {CurrentSchemaVersion}.");
            }

            if (version == 0)
            {
                await ApplyVersionOneAsync(connection, transaction, cancellationToken)
                    .ConfigureAwait(false);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ReputationStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ReputationStoreException(
                "The hash reputation database could not be initialized.",
                exception);
        }
    }

    public async ValueTask<HashReputationResult> LookupAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        if (!MalwareHashIndicator.TryNormalizeSha256(sha256, out var normalizedHash))
        {
            throw new ArgumentException(
                "A valid SHA-256 digest is required.",
                nameof(sha256));
        }

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT classification, malware_family, source, first_seen_utc, record_updated_utc
                FROM malicious_hashes
                WHERE sha256 = $sha256
                LIMIT 1;
                """;
            command.Parameters.AddWithValue("$sha256", normalizedHash!);

            await using var reader = await command
                .ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);

            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return HashReputationResult.Unknown();
            }

            var classificationText = reader.GetString(0);
            if (!Enum.TryParse<ThreatClassification>(
                    classificationText,
                    ignoreCase: false,
                    out var classification))
            {
                return HashReputationResult.LookupFailed(
                    "The database contains an unsupported threat classification.");
            }

            var malwareFamily = reader.IsDBNull(1) ? null : reader.GetString(1);
            var source = reader.GetString(2);
            var firstSeenUtc = reader.IsDBNull(3)
                ? (DateTimeOffset?)null
                : ParseTimestamp(reader.GetString(3));
            var recordUpdatedUtc = ParseTimestamp(reader.GetString(4));

            if (!MalwareHashIndicator.TryCreate(
                    normalizedHash,
                    classification,
                    source,
                    malwareFamily,
                    firstSeenUtc,
                    out var indicator,
                    out _))
            {
                return HashReputationResult.LookupFailed(
                    "The database contains invalid indicator metadata.");
            }

            return HashReputationResult.Malicious(indicator!, recordUpdatedUtc);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            return HashReputationResult.LookupFailed(
                "The hash reputation database could not be queried.");
        }
    }

    public async ValueTask<HashImportResult> ImportAsync(
        IReadOnlyCollection<MalwareHashIndicator> indicators,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(indicators);

        if (indicators.Count == 0)
        {
            return new HashImportResult(0, 0, 0);
        }

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO malicious_hashes (
                    sha256,
                    classification,
                    malware_family,
                    source,
                    first_seen_utc,
                    record_updated_utc)
                VALUES (
                    $sha256,
                    $classification,
                    $malware_family,
                    $source,
                    $first_seen_utc,
                    $record_updated_utc)
                ON CONFLICT(sha256) DO UPDATE SET
                    classification = excluded.classification,
                    malware_family = excluded.malware_family,
                    source = excluded.source,
                    first_seen_utc = excluded.first_seen_utc,
                    record_updated_utc = excluded.record_updated_utc
                WHERE malicious_hashes.classification <> excluded.classification
                    OR malicious_hashes.malware_family IS NOT excluded.malware_family
                    OR malicious_hashes.source <> excluded.source
                    OR malicious_hashes.first_seen_utc IS NOT excluded.first_seen_utc;
                """;

            var hashParameter = command.Parameters.Add("$sha256", SqliteType.Text);
            var classificationParameter = command.Parameters.Add("$classification", SqliteType.Text);
            var familyParameter = command.Parameters.Add("$malware_family", SqliteType.Text);
            var sourceParameter = command.Parameters.Add("$source", SqliteType.Text);
            var firstSeenParameter = command.Parameters.Add("$first_seen_utc", SqliteType.Text);
            var updatedParameter = command.Parameters.Add("$record_updated_utc", SqliteType.Text);

            var changedCount = 0;
            foreach (var indicator in indicators)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hashParameter.Value = indicator.Sha256;
                classificationParameter.Value = indicator.Classification.ToString();
                familyParameter.Value = indicator.MalwareFamily is null
                    ? DBNull.Value
                    : indicator.MalwareFamily;
                sourceParameter.Value = indicator.Source;
                firstSeenParameter.Value = indicator.FirstSeenUtc is null
                    ? DBNull.Value
                    : FormatTimestamp(indicator.FirstSeenUtc.Value);
                updatedParameter.Value = FormatTimestamp(DateTimeOffset.UtcNow);

                changedCount += await command
                    .ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

            return new HashImportResult(
                indicators.Count,
                changedCount,
                indicators.Count - changedCount);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ReputationStoreException(
                "The malicious-hash import transaction failed; no partial import was accepted.",
                exception);
        }
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Default,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = 5
        }.ToString();

        return new SqliteConnection(connectionString);
    }

    private static async ValueTask<long> ReadSchemaVersionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version;";
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    private static async ValueTask ApplyVersionOneAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        const string schema =
            """
            CREATE TABLE malicious_hashes (
                sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(length(sha256) = 64)
                    CHECK(sha256 NOT GLOB '*[^0-9a-f]*'),
                classification TEXT NOT NULL
                    CHECK(classification = 'Malware'),
                malware_family TEXT NULL
                    CHECK(malware_family IS NULL OR length(malware_family) BETWEEN 1 AND 200),
                source TEXT NOT NULL
                    CHECK(length(source) BETWEEN 1 AND 200),
                first_seen_utc TEXT NULL,
                record_updated_utc TEXT NOT NULL
            ) STRICT;

            CREATE INDEX ix_malicious_hashes_record_updated_utc
                ON malicious_hashes(record_updated_utc);

            PRAGMA user_version = 1;
            """;

        await ExecuteNonQueryAsync(
                connection,
                schema,
                transaction,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask ExecuteNonQueryAsync(
        SqliteConnection connection,
        string commandText,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.ParseExact(
            value,
            "O",
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind);

    private static bool IsStorageException(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException or FormatException;
}
