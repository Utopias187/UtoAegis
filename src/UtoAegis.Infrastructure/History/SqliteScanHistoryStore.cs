using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.History;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Infrastructure.History;

public sealed class SqliteScanHistoryStore : IScanHistoryStore
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumListLimit = 200;

    private readonly string _databasePath;

    public SqliteScanHistoryStore(string databasePath)
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
                throw new ScanHistoryStoreException(
                    $"History schema version {version} is newer than supported version {CurrentSchemaVersion}.");
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
        catch (ScanHistoryStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ScanHistoryStoreException(
                "The scan history database could not be initialized.",
                exception);
        }
    }

    public async ValueTask AppendAsync(
        ScanHistoryRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);

            await InsertScanAsync(connection, transaction, record, cancellationToken)
                .ConfigureAwait(false);
            await InsertFilesAsync(connection, transaction, record, cancellationToken)
                .ConfigureAwait(false);
            await InsertIssuesAsync(connection, transaction, record, cancellationToken)
                .ConfigureAwait(false);

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ScanHistoryStoreException(
                "The scan history record could not be stored; no partial record was accepted.",
                exception);
        }
    }

    public async ValueTask<IReadOnlyList<ScanHistorySummary>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > MaximumListLimit)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit),
                $"History list limit must be from 1 to {MaximumListLimit}.");
        }

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT id, target_kind, target_path, recursive, started_utc, completed_utc,
                       outcome, file_count, detected_file_count, failed_file_count,
                       issue_count, error_message
                FROM scan_history
                ORDER BY completed_utc DESC, id DESC
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", limit);

            var summaries = new List<ScanHistorySummary>();
            await using var reader = await command
                .ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                summaries.Add(ReadSummary(reader));
            }

            return summaries;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ScanHistoryStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ScanHistoryStoreException(
                "The scan history database could not be queried.",
                exception);
        }
    }

    public async ValueTask<ScanHistoryRecord?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A non-empty scan ID is required.", nameof(id));
        }

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);

            var header = await ReadHeaderAsync(connection, transaction, id, cancellationToken)
                .ConfigureAwait(false);
            if (header is null)
            {
                return null;
            }

            var files = await ReadFilesAsync(connection, transaction, id, cancellationToken)
                .ConfigureAwait(false);
            var issues = await ReadIssuesAsync(connection, transaction, id, cancellationToken)
                .ConfigureAwait(false);

            return ScanHistoryRecord.Restore(
                id,
                header.TargetKind,
                header.TargetPath,
                header.Recursive,
                header.StartedUtc,
                header.CompletedUtc,
                header.Outcome,
                files,
                issues,
                header.ErrorMessage);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ScanHistoryStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ScanHistoryStoreException(
                "The scan history record could not be read.",
                exception);
        }
    }

    public async ValueTask<ScanHistoryPruneResult> PruneAsync(
        DateTimeOffset completedBeforeUtc,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                DELETE FROM scan_history
                WHERE completed_utc < $completed_before_utc;
                """;
            command.Parameters.AddWithValue(
                "$completed_before_utc",
                FormatTimestamp(completedBeforeUtc));
            var deleted = await command
                .ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
            return new ScanHistoryPruneResult(deleted);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new ScanHistoryStoreException(
                "Old scan history records could not be pruned.",
                exception);
        }
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode) =>
        new(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Default,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = 5
        }.ToString());

    private static async ValueTask InsertScanAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScanHistoryRecord record,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO scan_history (
                id, target_kind, target_path, recursive, started_utc, completed_utc,
                outcome, file_count, detected_file_count, failed_file_count,
                issue_count, error_message)
            VALUES (
                $id, $target_kind, $target_path, $recursive, $started_utc, $completed_utc,
                $outcome, $file_count, $detected_file_count, $failed_file_count,
                $issue_count, $error_message);
            """;
        command.Parameters.AddWithValue("$id", FormatId(record.Id));
        command.Parameters.AddWithValue("$target_kind", record.TargetKind.ToString());
        command.Parameters.AddWithValue("$target_path", record.TargetPath);
        command.Parameters.AddWithValue("$recursive", record.Recursive ? 1 : 0);
        command.Parameters.AddWithValue("$started_utc", FormatTimestamp(record.StartedUtc));
        command.Parameters.AddWithValue("$completed_utc", FormatTimestamp(record.CompletedUtc));
        command.Parameters.AddWithValue("$outcome", record.Outcome.ToString());
        command.Parameters.AddWithValue("$file_count", record.Files.Count);
        command.Parameters.AddWithValue("$detected_file_count", record.DetectedFileCount);
        command.Parameters.AddWithValue("$failed_file_count", record.FailedFileCount);
        command.Parameters.AddWithValue("$issue_count", record.Issues.Count);
        command.Parameters.AddWithValue("$error_message", DbValue(record.ErrorMessage));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask InsertFilesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScanHistoryRecord record,
        CancellationToken cancellationToken)
    {
        await using var fileCommand = CreateFileInsertCommand(connection, transaction);
        await using var matchCommand = CreateMatchInsertCommand(connection, transaction);
        await fileCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await matchCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);

        for (var fileIndex = 0; fileIndex < record.Files.Count; fileIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var file = record.Files[fileIndex];
            SetFileParameters(fileCommand, record.Id, fileIndex, file);
            await fileCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            for (var matchIndex = 0; matchIndex < file.SignatureMatches.Count; matchIndex++)
            {
                SetMatchParameters(
                    matchCommand,
                    record.Id,
                    fileIndex,
                    matchIndex,
                    file.SignatureMatches[matchIndex]);
                await matchCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async ValueTask InsertIssuesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScanHistoryRecord record,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO scan_history_issues (scan_id, ordinal, path, kind, message)
            VALUES ($scan_id, $ordinal, $path, $kind, $message);
            """;
        command.Parameters.Add("$scan_id", SqliteType.Text);
        command.Parameters.Add("$ordinal", SqliteType.Integer);
        command.Parameters.Add("$path", SqliteType.Text);
        command.Parameters.Add("$kind", SqliteType.Text);
        command.Parameters.Add("$message", SqliteType.Text);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

        for (var index = 0; index < record.Issues.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var issue = record.Issues[index];
            command.Parameters["$scan_id"].Value = FormatId(record.Id);
            command.Parameters["$ordinal"].Value = index;
            command.Parameters["$path"].Value = issue.Path;
            command.Parameters["$kind"].Value = issue.Kind.ToString();
            command.Parameters["$message"].Value = issue.Message;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static SqliteCommand CreateFileInsertCommand(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO scan_history_files (
                scan_id, ordinal, path, hash_status, sha256, file_size_bytes,
                detected, completed, reputation_status, reputation_classification,
                reputation_malware_family, reputation_source, reputation_first_seen_utc,
                signature_status, signature_engine, signature_match_count,
                hash_error, reputation_error, signature_error)
            VALUES (
                $scan_id, $ordinal, $path, $hash_status, $sha256, $file_size_bytes,
                $detected, $completed, $reputation_status, $reputation_classification,
                $reputation_malware_family, $reputation_source, $reputation_first_seen_utc,
                $signature_status, $signature_engine, $signature_match_count,
                $hash_error, $reputation_error, $signature_error);
            """;
        foreach (var parameter in new[]
                 {
                     "$scan_id", "$path", "$hash_status", "$sha256", "$reputation_status",
                     "$reputation_classification", "$reputation_malware_family",
                     "$reputation_source", "$reputation_first_seen_utc", "$signature_status",
                     "$signature_engine", "$hash_error", "$reputation_error", "$signature_error"
                 })
        {
            command.Parameters.Add(parameter, SqliteType.Text);
        }

        foreach (var parameter in new[]
                 {
                     "$ordinal", "$file_size_bytes", "$detected", "$completed",
                     "$signature_match_count"
                 })
        {
            command.Parameters.Add(parameter, SqliteType.Integer);
        }

        return command;
    }

    private static SqliteCommand CreateMatchInsertCommand(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO scan_history_signature_matches (
                scan_id, file_ordinal, ordinal, rule_id, rule_name, source,
                byte_offset, pattern_length_bytes)
            VALUES (
                $scan_id, $file_ordinal, $ordinal, $rule_id, $rule_name, $source,
                $byte_offset, $pattern_length_bytes);
            """;
        command.Parameters.Add("$scan_id", SqliteType.Text);
        command.Parameters.Add("$file_ordinal", SqliteType.Integer);
        command.Parameters.Add("$ordinal", SqliteType.Integer);
        command.Parameters.Add("$rule_id", SqliteType.Text);
        command.Parameters.Add("$rule_name", SqliteType.Text);
        command.Parameters.Add("$source", SqliteType.Text);
        command.Parameters.Add("$byte_offset", SqliteType.Integer);
        command.Parameters.Add("$pattern_length_bytes", SqliteType.Integer);
        return command;
    }

    private static void SetFileParameters(
        SqliteCommand command,
        Guid scanId,
        int ordinal,
        ScanHistoryFile file)
    {
        command.Parameters["$scan_id"].Value = FormatId(scanId);
        command.Parameters["$ordinal"].Value = ordinal;
        command.Parameters["$path"].Value = file.Path;
        command.Parameters["$hash_status"].Value = file.HashStatus.ToString();
        command.Parameters["$sha256"].Value = DbValue(file.Sha256);
        command.Parameters["$file_size_bytes"].Value = DbValue(file.FileSizeBytes);
        command.Parameters["$detected"].Value = file.Detected ? 1 : 0;
        command.Parameters["$completed"].Value = file.Completed ? 1 : 0;
        command.Parameters["$reputation_status"].Value = DbValue(file.ReputationStatus?.ToString());
        command.Parameters["$reputation_classification"].Value =
            DbValue(file.ReputationClassification?.ToString());
        command.Parameters["$reputation_malware_family"].Value =
            DbValue(file.ReputationMalwareFamily);
        command.Parameters["$reputation_source"].Value = DbValue(file.ReputationSource);
        command.Parameters["$reputation_first_seen_utc"].Value =
            file.ReputationFirstSeenUtc is null
                ? DBNull.Value
                : FormatTimestamp(file.ReputationFirstSeenUtc.Value);
        command.Parameters["$signature_status"].Value = DbValue(file.SignatureStatus?.ToString());
        command.Parameters["$signature_engine"].Value = DbValue(file.SignatureEngine);
        command.Parameters["$signature_match_count"].Value = file.SignatureMatches.Count;
        command.Parameters["$hash_error"].Value = DbValue(file.HashError);
        command.Parameters["$reputation_error"].Value = DbValue(file.ReputationError);
        command.Parameters["$signature_error"].Value = DbValue(file.SignatureError);
    }

    private static void SetMatchParameters(
        SqliteCommand command,
        Guid scanId,
        int fileOrdinal,
        int ordinal,
        ScanHistorySignatureMatch match)
    {
        command.Parameters["$scan_id"].Value = FormatId(scanId);
        command.Parameters["$file_ordinal"].Value = fileOrdinal;
        command.Parameters["$ordinal"].Value = ordinal;
        command.Parameters["$rule_id"].Value = match.RuleId;
        command.Parameters["$rule_name"].Value = match.RuleName;
        command.Parameters["$source"].Value = match.Source;
        command.Parameters["$byte_offset"].Value = match.Offset;
        command.Parameters["$pattern_length_bytes"].Value = match.PatternLengthBytes;
    }

    private static async ValueTask<HistoryHeader?> ReadHeaderAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT target_kind, target_path, recursive, started_utc, completed_utc,
                   outcome, error_message
            FROM scan_history
            WHERE id = $id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$id", FormatId(id));
        await using var reader = await command
            .ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return new HistoryHeader(
            ReadEnum<ScanHistoryTargetKind>(reader.GetString(0), "target kind"),
            reader.GetString(1),
            reader.GetInt64(2) != 0,
            ParseTimestamp(reader.GetString(3)),
            ParseTimestamp(reader.GetString(4)),
            ReadEnum<ScanHistoryOutcome>(reader.GetString(5), "outcome"),
            reader.IsDBNull(6) ? null : reader.GetString(6));
    }

    private static async ValueTask<IReadOnlyList<ScanHistoryFile>> ReadFilesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT ordinal, path, hash_status, sha256, file_size_bytes, detected, completed,
                   reputation_status, reputation_classification, reputation_malware_family,
                   reputation_source, reputation_first_seen_utc, signature_status,
                   signature_engine, hash_error, reputation_error, signature_error
            FROM scan_history_files
            WHERE scan_id = $scan_id
            ORDER BY ordinal;
            """;
        command.Parameters.AddWithValue("$scan_id", FormatId(id));

        var rows = new List<FileRow>();
        await using (var reader = await command
                         .ExecuteReaderAsync(cancellationToken)
                         .ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                rows.Add(new FileRow(
                    reader.GetInt32(0),
                    reader.GetString(1),
                    ReadEnum<FileHashScanStatus>(reader.GetString(2), "hash status"),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? null : reader.GetInt64(4),
                    reader.GetInt64(5) != 0,
                    reader.GetInt64(6) != 0,
                    ReadNullableEnum<HashReputationStatus>(reader, 7, "reputation status"),
                    ReadNullableEnum<ThreatClassification>(reader, 8, "classification"),
                    reader.IsDBNull(9) ? null : reader.GetString(9),
                    reader.IsDBNull(10) ? null : reader.GetString(10),
                    reader.IsDBNull(11) ? null : ParseTimestamp(reader.GetString(11)),
                    ReadNullableEnum<SignatureScanStatus>(reader, 12, "signature status"),
                    reader.IsDBNull(13) ? null : reader.GetString(13),
                    reader.IsDBNull(14) ? null : reader.GetString(14),
                    reader.IsDBNull(15) ? null : reader.GetString(15),
                    reader.IsDBNull(16) ? null : reader.GetString(16)));
            }
        }

        var matchesByFile = await ReadMatchesAsync(
                connection,
                transaction,
                id,
                cancellationToken)
            .ConfigureAwait(false);
        var files = new List<ScanHistoryFile>(rows.Count);
        foreach (var row in rows)
        {
            matchesByFile.TryGetValue(row.Ordinal, out var matches);
            files.Add(new ScanHistoryFile(
                row.Path,
                row.HashStatus,
                row.Sha256,
                row.FileSizeBytes,
                row.Detected,
                row.Completed,
                row.ReputationStatus,
                row.ReputationClassification,
                row.ReputationMalwareFamily,
                row.ReputationSource,
                row.ReputationFirstSeenUtc,
                row.SignatureStatus,
                row.SignatureEngine,
                matches ?? [],
                row.HashError,
                row.ReputationError,
                row.SignatureError));
        }

        return files;
    }

    private static async ValueTask<IReadOnlyDictionary<int, IReadOnlyList<ScanHistorySignatureMatch>>> ReadMatchesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid scanId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT file_ordinal, rule_id, rule_name, source, byte_offset, pattern_length_bytes
            FROM scan_history_signature_matches
            WHERE scan_id = $scan_id
            ORDER BY file_ordinal, ordinal;
            """;
        command.Parameters.AddWithValue("$scan_id", FormatId(scanId));

        var matches = new Dictionary<int, List<ScanHistorySignatureMatch>>();
        await using var reader = await command
            .ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var fileOrdinal = reader.GetInt32(0);
            if (!matches.TryGetValue(fileOrdinal, out var fileMatches))
            {
                fileMatches = [];
                matches.Add(fileOrdinal, fileMatches);
            }

            fileMatches.Add(new ScanHistorySignatureMatch(
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt64(4),
                reader.GetInt32(5)));
        }

        return matches.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<ScanHistorySignatureMatch>)pair.Value);
    }

    private static async ValueTask<IReadOnlyList<ScanHistoryIssue>> ReadIssuesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid scanId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT path, kind, message
            FROM scan_history_issues
            WHERE scan_id = $scan_id
            ORDER BY ordinal;
            """;
        command.Parameters.AddWithValue("$scan_id", FormatId(scanId));

        var issues = new List<ScanHistoryIssue>();
        await using var reader = await command
            .ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            issues.Add(new ScanHistoryIssue(
                reader.GetString(0),
                ReadEnum<DirectoryScanIssueKind>(reader.GetString(1), "issue kind"),
                reader.GetString(2)));
        }

        return issues;
    }

    private static ScanHistorySummary ReadSummary(SqliteDataReader reader) =>
        new(
            ParseId(reader.GetString(0)),
            ReadEnum<ScanHistoryTargetKind>(reader.GetString(1), "target kind"),
            reader.GetString(2),
            reader.GetInt64(3) != 0,
            ParseTimestamp(reader.GetString(4)),
            ParseTimestamp(reader.GetString(5)),
            ReadEnum<ScanHistoryOutcome>(reader.GetString(6), "outcome"),
            reader.GetInt32(7),
            reader.GetInt32(8),
            reader.GetInt32(9),
            reader.GetInt32(10),
            reader.IsDBNull(11) ? null : reader.GetString(11));

    private static TEnum ReadEnum<TEnum>(string value, string fieldName)
        where TEnum : struct, Enum
    {
        if (Enum.TryParse<TEnum>(value, ignoreCase: false, out var parsed) &&
            Enum.IsDefined(parsed))
        {
            return parsed;
        }

        throw new ScanHistoryStoreException(
            $"The history database contains an unsupported {fieldName} value.");
    }

    private static TEnum? ReadNullableEnum<TEnum>(
        SqliteDataReader reader,
        int ordinal,
        string fieldName)
        where TEnum : struct, Enum =>
        reader.IsDBNull(ordinal)
            ? null
            : ReadEnum<TEnum>(reader.GetString(ordinal), fieldName);

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
            CREATE TABLE scan_history (
                id TEXT NOT NULL PRIMARY KEY CHECK(length(id) = 36),
                target_kind TEXT NOT NULL CHECK(target_kind IN ('File', 'Directory')),
                target_path TEXT NOT NULL CHECK(length(target_path) > 0),
                recursive INTEGER NOT NULL CHECK(recursive IN (0, 1)),
                started_utc TEXT NOT NULL,
                completed_utc TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN ('Completed', 'Partial', 'Failed')),
                file_count INTEGER NOT NULL CHECK(file_count >= 0),
                detected_file_count INTEGER NOT NULL CHECK(detected_file_count >= 0),
                failed_file_count INTEGER NOT NULL CHECK(failed_file_count >= 0),
                issue_count INTEGER NOT NULL CHECK(issue_count >= 0),
                error_message TEXT NULL
            ) STRICT;

            CREATE INDEX ix_scan_history_completed_utc
                ON scan_history(completed_utc DESC);

            CREATE TABLE scan_history_files (
                scan_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                path TEXT NOT NULL CHECK(length(path) > 0),
                hash_status TEXT NOT NULL,
                sha256 TEXT NULL CHECK(sha256 IS NULL OR length(sha256) = 64),
                file_size_bytes INTEGER NULL CHECK(file_size_bytes IS NULL OR file_size_bytes >= 0),
                detected INTEGER NOT NULL CHECK(detected IN (0, 1)),
                completed INTEGER NOT NULL CHECK(completed IN (0, 1)),
                reputation_status TEXT NULL,
                reputation_classification TEXT NULL,
                reputation_malware_family TEXT NULL,
                reputation_source TEXT NULL,
                reputation_first_seen_utc TEXT NULL,
                signature_status TEXT NULL,
                signature_engine TEXT NULL,
                signature_match_count INTEGER NOT NULL CHECK(signature_match_count >= 0),
                hash_error TEXT NULL,
                reputation_error TEXT NULL,
                signature_error TEXT NULL,
                PRIMARY KEY(scan_id, ordinal),
                FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
            ) STRICT;

            CREATE INDEX ix_scan_history_files_sha256
                ON scan_history_files(sha256) WHERE sha256 IS NOT NULL;
            CREATE INDEX ix_scan_history_files_detected
                ON scan_history_files(detected) WHERE detected = 1;

            CREATE TABLE scan_history_signature_matches (
                scan_id TEXT NOT NULL,
                file_ordinal INTEGER NOT NULL CHECK(file_ordinal >= 0),
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                source TEXT NOT NULL,
                byte_offset INTEGER NOT NULL CHECK(byte_offset >= 0),
                pattern_length_bytes INTEGER NOT NULL CHECK(pattern_length_bytes > 0),
                PRIMARY KEY(scan_id, file_ordinal, ordinal),
                FOREIGN KEY(scan_id, file_ordinal)
                    REFERENCES scan_history_files(scan_id, ordinal) ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE scan_history_issues (
                scan_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                PRIMARY KEY(scan_id, ordinal),
                FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
            ) STRICT;

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

    private static object DbValue(object? value) => value ?? DBNull.Value;

    private static string FormatId(Guid id) => id.ToString("D", CultureInfo.InvariantCulture);

    private static Guid ParseId(string value)
    {
        if (Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty)
        {
            return id;
        }

        throw new ScanHistoryStoreException("The history database contains an invalid scan ID.");
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value)
    {
        try
        {
            return DateTimeOffset.ParseExact(
                value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
        }
        catch (FormatException exception)
        {
            throw new ScanHistoryStoreException(
                "The history database contains an invalid timestamp.",
                exception);
        }
    }

    private static bool IsStorageException(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException;

    private sealed record HistoryHeader(
        ScanHistoryTargetKind TargetKind,
        string TargetPath,
        bool Recursive,
        DateTimeOffset StartedUtc,
        DateTimeOffset CompletedUtc,
        ScanHistoryOutcome Outcome,
        string? ErrorMessage);

    private sealed record FileRow(
        int Ordinal,
        string Path,
        FileHashScanStatus HashStatus,
        string? Sha256,
        long? FileSizeBytes,
        bool Detected,
        bool Completed,
        HashReputationStatus? ReputationStatus,
        ThreatClassification? ReputationClassification,
        string? ReputationMalwareFamily,
        string? ReputationSource,
        DateTimeOffset? ReputationFirstSeenUtc,
        SignatureScanStatus? SignatureStatus,
        string? SignatureEngine,
        string? HashError,
        string? ReputationError,
        string? SignatureError);
}
