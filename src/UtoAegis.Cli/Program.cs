using System.Text.Json;
using System.Text.Json.Nodes;
using UtoAegis.Cli;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Quarantine;
using UtoAegis.Core.Response;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;
using UtoAegis.Infrastructure.Importing;
using UtoAegis.Infrastructure.History;
using UtoAegis.Infrastructure.Monitoring;
using UtoAegis.Infrastructure.Quarantine;
using UtoAegis.Infrastructure.Reputation;
using UtoAegis.Infrastructure.Signatures;
using UtoAegis.Infrastructure.ThreatIntelligence;

if (!CliOptions.TryParse(args, out var options, out var parseError))
{
    Console.Error.WriteLine(parseError);
    PrintUsage();
    return ExitCodes.UsageError;
}

if (options!.ShowHelp)
{
    PrintUsage();
    return ExitCodes.Success;
}

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

try
{
    return options.Command switch
    {
        CliCommand.Scan => await RunScanAsync(options, cancellation.Token),
        CliCommand.ScanDirectory => await RunDirectoryScanAsync(options, cancellation.Token),
        CliCommand.Monitor => await RunMonitorAsync(options, cancellation.Token),
        CliCommand.ImportHashes => await RunImportAsync(options, cancellation.Token),
        CliCommand.HistoryList => await HistoryCommandRunner.ListAsync(options, cancellation.Token),
        CliCommand.HistoryShow => await HistoryCommandRunner.ShowAsync(options, cancellation.Token),
        CliCommand.HistoryPrune => await HistoryCommandRunner.PruneAsync(options, cancellation.Token),
        CliCommand.QuarantineAdd => await RunQuarantineAddAsync(options, cancellation.Token),
        CliCommand.QuarantineList => await QuarantineCommandRunner.ListAsync(options, cancellation.Token),
        CliCommand.QuarantineShow => await QuarantineCommandRunner.ShowAsync(options, cancellation.Token),
        CliCommand.QuarantineRestore => await QuarantineCommandRunner.RestoreAsync(options, cancellation.Token),
        CliCommand.UpdateApply => await ThreatUpdateCommandRunner.ApplyAsync(options, cancellation.Token),
        CliCommand.UpdateStatus => await ThreatUpdateCommandRunner.StatusAsync(options, cancellation.Token),
        CliCommand.UpdateRollback => await ThreatUpdateCommandRunner.RollbackAsync(options, cancellation.Token),
        _ => ExitCodes.UsageError
    };
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Operation cancelled.");
    return ExitCodes.Cancelled;
}
catch (IndicatorImportException exception)
{
    Console.Error.WriteLine($"Import rejected: {exception.Message}");
    return ExitCodes.ImportFailed;
}
catch (SignatureRuleFileException exception)
{
    Console.Error.WriteLine($"Signature rules rejected: {exception.Message}");
    return ExitCodes.SignatureScanFailed;
}
catch (ReputationStoreException exception)
{
    Console.Error.WriteLine($"Reputation database error: {exception.Message}");
    return options.Command == CliCommand.ImportHashes
        ? ExitCodes.ImportFailed
        : ExitCodes.ReputationLookupFailed;
}
catch (ScanHistoryStoreException exception)
{
    Console.Error.WriteLine($"Scan history error: {exception.Message}");
    return ExitCodes.HistoryStoreFailed;
}
catch (QuarantineStoreException exception)
{
    Console.Error.WriteLine($"Quarantine vault error: {exception.Message}");
    return ExitCodeResolver.ForOperationFailure(options.Command);
}
catch (ThreatUpdateException exception)
{
    Console.Error.WriteLine($"Threat update rejected: {exception.Message}");
    return ExitCodes.ThreatUpdateFailed;
}
catch (ArgumentException exception)
{
    Console.Error.WriteLine($"Invalid argument: {exception.Message}");
    return ExitCodeResolver.ForOperationFailure(options.Command);
}
catch (UnauthorizedAccessException)
{
    Console.Error.WriteLine("The operation was denied by the file system.");
    return ExitCodeResolver.ForOperationFailure(options.Command);
}
catch (IOException)
{
    Console.Error.WriteLine("The operation failed because a file could not be read or written.");
    return ExitCodeResolver.ForOperationFailure(options.Command);
}

static async Task<int> RunScanAsync(CliOptions options, CancellationToken cancellationToken)
{
    var scanId = Guid.NewGuid();
    var startedUtc = DateTimeOffset.UtcNow;
    var historyStore = await CreateHistoryStoreAsync(options, cancellationToken);
    if (!options.Quiet)
    {
        JsonLogWriter.ScanStarted(scanId, options.InputPath!);
    }

    var scanner = await CreateFileScannerAsync(options, scanId, cancellationToken);
    var result = await scanner.ScanAsync(options.InputPath!, cancellationToken);
    var completedUtc = DateTimeOffset.UtcNow;

    if (!options.Quiet)
    {
        JsonLogWriter.ScanFinished(scanId, result.FileHash, result.Reputation);
        if (result.Signatures is not null)
        {
            JsonLogWriter.SignatureScanFinished(scanId, result.Signatures);
        }
    }

    var history = await PersistHistoryAsync(
        options,
        historyStore,
        ScanHistoryRecord.FromFileScan(
            scanId,
            options.InputPath!,
            startedUtc,
            completedUtc,
            result),
        cancellationToken);
    WriteScanResult(options.Json, result, scanId, history);
    return history.Requested && !history.Stored
        ? ExitCodeResolver.ForHistoryWriteFailure(result.IsDetected)
        : ExitCodeResolver.ForFile(result);
}

static async Task<int> RunDirectoryScanAsync(
    CliOptions options,
    CancellationToken cancellationToken)
{
    var scanId = Guid.NewGuid();
    var startedUtc = DateTimeOffset.UtcNow;
    var historyStore = await CreateHistoryStoreAsync(options, cancellationToken);
    if (!options.Quiet)
    {
        JsonLogWriter.DirectoryScanStarted(
            scanId,
            options.InputPath!,
            options.Recursive,
            options.MaximumConcurrency);
    }

    var fileScanner = await CreateFileScannerAsync(options, scanId, cancellationToken);
    var directoryScanner = new DirectoryScanner(
        fileScanner,
        new DirectoryScanOptions(
            recurse: options.Recursive,
            maximumConcurrency: options.MaximumConcurrency,
            excludedPaths: DirectoryScanExclusions(options)));
    var result = await directoryScanner.ScanAsync(options.InputPath!, cancellationToken);
    var completedUtc = DateTimeOffset.UtcNow;

    if (!options.Quiet)
    {
        JsonLogWriter.DirectoryScanFinished(scanId, result);
    }

    var history = await PersistHistoryAsync(
        options,
        historyStore,
        ScanHistoryRecord.FromDirectoryScan(
            scanId,
            options.InputPath!,
            options.Recursive,
            startedUtc,
            completedUtc,
            result),
        cancellationToken);
    WriteDirectoryScanResult(options.Json, options, result, scanId, history);
    return history.Requested && !history.Stored
        ? ExitCodeResolver.ForHistoryWriteFailure(result.HasDetections)
        : ExitCodeResolver.ForDirectory(result);
}

static async Task<int> RunQuarantineAddAsync(
    CliOptions options,
    CancellationToken cancellationToken)
{
    var scanId = Guid.NewGuid();
    var startedUtc = DateTimeOffset.UtcNow;
    var historyStore = await CreateHistoryStoreAsync(options, cancellationToken);
    if (!options.Quiet)
    {
        JsonLogWriter.ScanStarted(scanId, options.InputPath!);
    }

    var scanner = await CreateFileScannerAsync(options, scanId, cancellationToken);
    var result = await scanner.ScanAsync(options.InputPath!, cancellationToken);
    var completedUtc = DateTimeOffset.UtcNow;
    if (!options.Quiet)
    {
        JsonLogWriter.ScanFinished(scanId, result.FileHash, result.Reputation);
        if (result.Signatures is not null)
        {
            JsonLogWriter.SignatureScanFinished(scanId, result.Signatures);
        }
    }

    var history = await PersistHistoryAsync(
        options,
        historyStore,
        ScanHistoryRecord.FromFileScan(
            scanId,
            options.InputPath!,
            startedUtc,
            completedUtc,
            result),
        cancellationToken);

    if (!result.IsCompleted || !result.IsDetected)
    {
        WriteQuarantineAddResult(options, scanId, result, history, quarantine: null);
        if (history.Requested && !history.Stored)
        {
            return ExitCodeResolver.ForHistoryWriteFailure(result.IsDetected);
        }

        return ExitCodeResolver.ForFile(result);
    }

    using var store = new FileSystemQuarantineStore(options.VaultPath!);
    await store.InitializeAsync(cancellationToken);
    var evidence = DetectionEvidence.FromFileScan(result);
    var quarantine = await store.QuarantineAsync(
        new QuarantineRequest(
            result.FileHash.Path!,
            result.FileHash.Sha256!,
            result.FileHash.FileSizeBytes!.Value,
            evidence),
        cancellationToken);
    if (!options.Quiet)
    {
        JsonLogWriter.QuarantineFinished(scanId, quarantine);
    }

    WriteQuarantineAddResult(options, scanId, result, history, quarantine);

    if (!quarantine.IsSuccess)
    {
        return ExitCodes.QuarantineFailed;
    }

    return history.Requested && !history.Stored
        ? ExitCodes.ThreatDetectedWithHistoryFailure
        : ExitCodes.Quarantined;
}

static void WriteQuarantineAddResult(
    CliOptions options,
    Guid scanId,
    FileScanResult scan,
    HistoryPersistenceResult history,
    QuarantineOperationResult? quarantine)
{
    if (options.Json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
                status = quarantine?.Status.ToString() ??
                    (scan.IsDetected ? "ScanFailed" : "NotDetected"),
                scanId,
                scan = CreateFileScanPayload(scan),
                history = CreateHistoryPersistencePayload(history),
                quarantine = quarantine is null
                    ? null
                    : new
                    {
                        status = quarantine.Status.ToString(),
                        entry = quarantine.Entry is null
                            ? null
                            : QuarantineCommandRunner.CreateEntryPayload(quarantine.Entry),
                        error = quarantine.ErrorMessage
                    }
            },
            CliJson.ResultOptions));
        return;
    }

    WriteHumanFileDetails(scan);
    WriteHumanHistoryStatus(scanId, history);
    if (quarantine?.IsSuccess == true)
    {
        Console.WriteLine(
            $"Quarantined as {quarantine.Entry!.Id:D} in " +
            $"{Path.GetFullPath(options.VaultPath!)}.");
    }
    else if (quarantine is not null)
    {
        Console.Error.WriteLine(
            $"Quarantine failed ({quarantine.Status}): {quarantine.ErrorMessage}");
    }
    else if (!scan.IsDetected)
    {
        Console.WriteLine("The file was not quarantined because no configured detector matched.");
    }
}

static async Task<int> RunMonitorAsync(
    CliOptions options,
    CancellationToken cancellationToken)
{
    var sessionId = Guid.NewGuid();
    var historyStore = await CreateHistoryStoreAsync(options, cancellationToken);
    var fileScanner = await CreateFileScannerAsync(options, sessionId, cancellationToken);
    var excludedPaths = DirectoryScanExclusions(options);
    var directoryScanner = new DirectoryScanner(
        fileScanner,
        new DirectoryScanOptions(
            recurse: options.Recursive,
            maximumConcurrency: options.MaximumConcurrency,
            excludedPaths: excludedPaths));
    var sink = new CliFileMonitorSink(sessionId, options, historyStore);
    var engine = new FileMonitoringEngine(
        fileScanner,
        directoryScanner,
        sink,
        new FileMonitorOptions(
            TimeSpan.FromMilliseconds(options.DebounceMilliseconds),
            runInitialScan: true,
            excludedPaths));
    await using var source = new FileSystemWatcherEventSource(
        options.InputPath!,
        options.Recursive,
        options.MonitorQueueCapacity,
        excludedPaths: excludedPaths);

    if (!options.Quiet)
    {
        JsonLogWriter.MonitorStarted(
            sessionId,
            options.InputPath!,
            options.Recursive,
            options.DebounceMilliseconds,
            options.MonitorQueueCapacity);
    }

    if (!options.Json)
    {
        Console.WriteLine(
            $"Monitoring {Path.GetFullPath(options.InputPath!)} " +
            $"(session {sessionId:D}). Press Ctrl+C to stop.");
    }

    FileMonitorSummary summary;
    try
    {
        summary = await engine.RunAsync(options.InputPath!, source, cancellationToken);
    }
    catch (OperationCanceledException)
    {
        if (!options.Quiet)
        {
            JsonLogWriter.MonitorCancelled(sessionId);
        }

        throw;
    }

    if (!options.Quiet)
    {
        JsonLogWriter.MonitorStopped(sessionId, summary);
    }

    if (sink.HistoryWriteFailed)
    {
        return ExitCodeResolver.ForHistoryWriteFailure(sink.HasDetections);
    }

    return sink.HasDetections ? ExitCodes.ThreatDetected : ExitCodes.Success;
}

static async ValueTask<IFileScanner> CreateFileScannerAsync(
    CliOptions options,
    Guid scanId,
    CancellationToken cancellationToken)
{
    IHashReputationStore? reputationStore = null;
    if (options.DatabasePath is not null)
    {
        var store = new SqliteHashReputationStore(options.DatabasePath);
        await store.InitializeAsync(cancellationToken);
        reputationStore = store;
    }

    ISignatureScanner? signatureScanner = null;
    if (options.SignaturePath is not null)
    {
        var ruleFile = await JsonLinesSignatureRuleReader.ReadAsync(
            options.SignaturePath,
            cancellationToken);
        signatureScanner = new FixedByteSignatureScanner(ruleFile.Rules);
        if (!options.Quiet)
        {
            JsonLogWriter.SignatureRulesLoaded(
                scanId,
                options.SignaturePath,
                ruleFile.Rules.Count,
                ruleFile.DuplicateCount);
        }
    }

    return new CompositeFileScanner(
        new Sha256FileHashScanner(),
        reputationStore,
        signatureScanner);
}

static async ValueTask<IScanHistoryStore?> CreateHistoryStoreAsync(
    CliOptions options,
    CancellationToken cancellationToken)
{
    if (options.HistoryPath is null)
    {
        return null;
    }

    string historyPath;
    try
    {
        historyPath = Path.GetFullPath(options.HistoryPath);
        foreach (var conflictingPath in HistoryConflictingPaths(options))
        {
            if (PathsEqual(historyPath, conflictingPath))
            {
                throw new ScanHistoryStoreException(
                    "The history database must be separate from scan inputs, rule files, and the reputation database.");
            }
        }
    }
    catch (ScanHistoryStoreException)
    {
        throw;
    }
    catch (Exception exception) when (
        exception is ArgumentException or NotSupportedException or PathTooLongException)
    {
        throw new ScanHistoryStoreException(
            "The history database path is invalid.",
            exception);
    }

    var store = new SqliteScanHistoryStore(historyPath);
    await store.InitializeAsync(cancellationToken);
    return store;
}

static IEnumerable<string> HistoryConflictingPaths(CliOptions options)
{
    if (options.DatabasePath is not null)
    {
        yield return Path.GetFullPath(options.DatabasePath);
    }

    if (options.SignaturePath is not null)
    {
        yield return Path.GetFullPath(options.SignaturePath);
    }

    if (options.Command == CliCommand.Scan && options.InputPath is not null)
    {
        yield return Path.GetFullPath(options.InputPath);
    }
}

static bool PathsEqual(string first, string second) =>
    string.Equals(
        first,
        second,
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal);

static async ValueTask<HistoryPersistenceResult> PersistHistoryAsync(
    CliOptions options,
    IScanHistoryStore? store,
    ScanHistoryRecord record,
    CancellationToken cancellationToken)
{
    if (store is null || options.HistoryPath is null)
    {
        return new HistoryPersistenceResult(false, false, null, null);
    }

    try
    {
        await store.AppendAsync(record, cancellationToken);
        if (!options.Quiet)
        {
            JsonLogWriter.HistoryStored(record, options.HistoryPath);
        }

        return new HistoryPersistenceResult(
            true,
            true,
            Path.GetFullPath(options.HistoryPath),
            null);
    }
    catch (ScanHistoryStoreException exception)
    {
        Console.Error.WriteLine($"Scan completed, but history storage failed: {exception.Message}");
        if (!options.Quiet)
        {
            JsonLogWriter.HistoryStoreFailed(record.Id, options.HistoryPath, exception.Message);
        }

        return new HistoryPersistenceResult(
            true,
            false,
            Path.GetFullPath(options.HistoryPath),
            exception.Message);
    }
}

static IReadOnlyCollection<string> DirectoryScanExclusions(CliOptions options)
{
    var paths = new List<string>();
    if (options.SignaturePath is not null)
    {
        paths.Add(Path.GetFullPath(options.SignaturePath));
    }

    if (options.DatabasePath is not null)
    {
        var databasePath = Path.GetFullPath(options.DatabasePath);
        paths.Add(databasePath);
        paths.Add(databasePath + "-shm");
        paths.Add(databasePath + "-wal");
    }

    if (options.HistoryPath is not null)
    {
        var historyPath = Path.GetFullPath(options.HistoryPath);
        paths.Add(historyPath);
        paths.Add(historyPath + "-shm");
        paths.Add(historyPath + "-wal");
    }

    return paths;
}

static async Task<int> RunImportAsync(CliOptions options, CancellationToken cancellationToken)
{
    var importFile = await JsonLinesIndicatorReader.ReadAsync(
        options.InputPath!,
        cancellationToken);
    var store = new SqliteHashReputationStore(options.DatabasePath!);
    await store.InitializeAsync(cancellationToken);
    var result = await store.ImportAsync(importFile.Indicators, cancellationToken);

    if (!options.Quiet)
    {
        JsonLogWriter.ImportFinished(options.DatabasePath!, result, importFile.DuplicateCount);
    }

    if (options.Json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
                status = "Imported",
                databasePath = Path.GetFullPath(options.DatabasePath!),
                uniqueIndicators = result.ProcessedCount,
                changedIndicators = result.ChangedCount,
                unchangedIndicators = result.UnchangedCount,
                duplicateInputLines = importFile.DuplicateCount
            },
            CliJson.ResultOptions));
    }
    else
    {
        Console.WriteLine(
            $"Imported {result.ProcessedCount} unique indicator(s): " +
            $"{result.ChangedCount} changed, {result.UnchangedCount} unchanged, " +
            $"{importFile.DuplicateCount} duplicate input line(s) ignored.");
    }

    return ExitCodes.Success;
}

static void WriteScanResult(
    bool json,
    FileScanResult result,
    Guid scanId,
    HistoryPersistenceResult history)
{
    if (json)
    {
        var payload = JsonSerializer.SerializeToNode(
            CreateFileScanPayload(result),
            CliJson.ResultOptions)!.AsObject();
        payload["scanId"] = JsonValue.Create(scanId);
        payload["history"] = CreateHistoryPersistencePayload(history);
        Console.WriteLine(payload.ToJsonString(CliJson.ResultOptions));
        return;
    }

    WriteHumanFileDetails(result);
    WriteHumanHistoryStatus(scanId, history);
}

static void WriteDirectoryScanResult(
    bool json,
    CliOptions options,
    DirectoryScanResult result,
    Guid scanId,
    HistoryPersistenceResult history)
{
    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
                scanId,
                status = result.Status.ToString(),
                rootPath = result.RootPath,
                recursive = options.Recursive,
                maximumConcurrency = options.MaximumConcurrency,
                elapsedMilliseconds = result.Elapsed.TotalMilliseconds,
                error = result.ErrorMessage,
                summary = new
                {
                    fileCount = result.Files.Count,
                    detectedFileCount = result.DetectedFileCount,
                    failedFileCount = result.FailedFileCount,
                    issueCount = result.Issues.Count
                },
                history = CreateHistoryPersistencePayload(history),
                issues = result.Issues.Select(issue => new
                {
                    path = issue.Path,
                    kind = issue.Kind.ToString(),
                    message = issue.Message
                }),
                files = result.Files.Select(file => CreateFileScanPayload(file.Result))
            },
            CliJson.ResultOptions));
        return;
    }

    if (!result.IsCompleted)
    {
        Console.Error.WriteLine(
            $"Directory scan failed ({result.Status}): {result.ErrorMessage}");
        WriteDirectoryIssues(result.Issues);
        WriteHumanHistoryStatus(scanId, history);
        return;
    }

    Console.WriteLine(
        $"Directory scan {result.Status}: {result.Files.Count} file(s), " +
        $"{result.DetectedFileCount} detection(s), {result.FailedFileCount} file failure(s), " +
        $"{result.Issues.Count} traversal issue(s).");

    foreach (var file in result.Files)
    {
        var label = file.Result.IsDetected
            ? "DETECTED"
            : file.Result.IsCompleted
                ? "NO DETECTION"
                : "FAILED";
        Console.WriteLine($"[{label}] {file.Path}");
        if (file.Result.IsDetected || !file.Result.IsCompleted)
        {
            WriteHumanDetectionAndFailures(file.Result, "  ");
        }
    }

    WriteDirectoryIssues(result.Issues);
    WriteHumanHistoryStatus(scanId, history);
}

static JsonNode? CreateHistoryPersistencePayload(HistoryPersistenceResult history) =>
    history.Requested
        ? JsonSerializer.SerializeToNode(
            new
            {
                stored = history.Stored,
                databasePath = history.DatabasePath,
                error = history.ErrorMessage
            },
            CliJson.ResultOptions)
        : null;

static void WriteHumanHistoryStatus(Guid scanId, HistoryPersistenceResult history)
{
    if (!history.Requested)
    {
        return;
    }

    if (history.Stored)
    {
        Console.WriteLine($"History: stored scan {scanId:D} in {history.DatabasePath}");
    }
    else
    {
        Console.Error.WriteLine($"History: scan {scanId:D} was not stored.");
    }
}

static object CreateFileScanPayload(FileScanResult result)
{
    var hash = result.FileHash;
    var reputation = result.Reputation;
    var signatures = result.Signatures;
    return new
    {
        status = hash.Status.ToString(),
        path = hash.Path,
        algorithm = hash.IsSuccess ? "SHA-256" : null,
        sha256 = hash.Sha256,
        fileSizeBytes = hash.FileSizeBytes,
        elapsedMilliseconds = hash.Elapsed.TotalMilliseconds,
        error = hash.ErrorMessage,
        detected = result.IsDetected,
        completed = result.IsCompleted,
        reputation = reputation is null
            ? null
            : new
            {
                status = reputation.Status.ToString(),
                classification = reputation.Indicator?.Classification.ToString(),
                malwareFamily = reputation.Indicator?.MalwareFamily,
                source = reputation.Indicator?.Source,
                firstSeenUtc = reputation.Indicator?.FirstSeenUtc,
                recordUpdatedUtc = reputation.RecordUpdatedUtc,
                error = reputation.ErrorMessage
            },
        signatures = signatures is null
            ? null
            : new
            {
                status = signatures.Status.ToString(),
                engine = signatures.EngineName,
                fileSizeBytes = signatures.FileSizeBytes,
                elapsedMilliseconds = signatures.Elapsed.TotalMilliseconds,
                error = signatures.ErrorMessage,
                matches = signatures.Matches.Select(match => new
                {
                    ruleId = match.RuleId,
                    ruleName = match.RuleName,
                    source = match.Source,
                    offset = match.Offset,
                    patternLengthBytes = match.PatternLengthBytes
                })
            }
    };
}

static void WriteHumanFileDetails(FileScanResult result)
{
    if (!result.FileHash.IsSuccess)
    {
        Console.Error.WriteLine(
            $"Scan failed ({result.FileHash.Status}): {result.FileHash.ErrorMessage}");
        return;
    }

    Console.WriteLine($"{result.FileHash.Sha256}  {result.FileHash.Path}");
    WriteHumanDetectionAndFailures(result, string.Empty);

    if (result.Reputation?.Status == HashReputationStatus.Unknown)
    {
        Console.WriteLine("Reputation: UNKNOWN (not present in the configured database)");
    }

    if (result.Signatures?.Status == SignatureScanStatus.NoMatch)
    {
        Console.WriteLine("Signatures: NO MATCH (no configured exact-byte rule matched)");
    }
}

static void WriteHumanDetectionAndFailures(FileScanResult result, string indent)
{
    if (!result.FileHash.IsSuccess)
    {
        Console.Error.WriteLine(
            $"{indent}Hash scan failed ({result.FileHash.Status}): " +
            result.FileHash.ErrorMessage);
        return;
    }

    if (result.Reputation?.Status == HashReputationStatus.Malicious)
    {
        var family = result.Reputation.Indicator!.MalwareFamily ?? "unspecified family";
        Console.WriteLine(
            $"{indent}Reputation: MALICIOUS " +
            $"({family}; source: {result.Reputation.Indicator.Source})");
    }
    else if (result.Reputation?.Status == HashReputationStatus.LookupFailed)
    {
        Console.Error.WriteLine(
            $"{indent}Reputation lookup failed: {result.Reputation.ErrorMessage}");
    }

    if (result.Signatures?.Status == SignatureScanStatus.Detected)
    {
        Console.WriteLine(
            $"{indent}Signatures: DETECTED " +
            $"({result.Signatures.Matches.Count} rule match(es))");
        foreach (var match in result.Signatures.Matches)
        {
            Console.WriteLine(
                $"{indent}  {match.RuleId} at byte {match.Offset} " +
                $"({match.RuleName}; source: {match.Source})");
        }
    }
    else if (result.Signatures is { IsCompleted: false })
    {
        Console.Error.WriteLine(
            $"{indent}Signature scan failed ({result.Signatures.Status}): " +
            result.Signatures.ErrorMessage);
    }
}

static void WriteDirectoryIssues(IReadOnlyList<DirectoryScanIssue> issues)
{
    foreach (var issue in issues)
    {
        Console.Error.WriteLine($"[{issue.Kind}] {issue.Path}: {issue.Message}");
    }
}

static void PrintUsage()
{
    Console.WriteLine(
        """
        UtoAegis file, directory, real-time, reputation, signature, and history scanner

        Usage:
          utoaegis [scan] [--database <path>] [--signatures <path>] [--history <path>] [--json] [--quiet] [--] <file>
          utoaegis scan-directory [--recursive] [--max-concurrency <1-32>] [--database <path>] [--signatures <path>] [--history <path>] [--json] [--quiet] [--] <directory>
          utoaegis monitor [--recursive] [--max-concurrency <1-32>] [--debounce-ms <0-60000>] [--queue-capacity <1-65536>] [--database <path>] [--signatures <path>] [--history <path>] [--json] [--quiet] [--] <directory>
          utoaegis quarantine add --vault <path> [--database <path>] [--signatures <path>] [--history <path>] [--json] [--quiet] [--] <file>
          utoaegis quarantine list --vault <path> [--limit <1-200>] [--json]
          utoaegis quarantine show --vault <path> [--json] <quarantine-id>
          utoaegis quarantine restore --vault <path> [--destination <path>] [--json] <quarantine-id>
          utoaegis import-hashes --database <path> [--json] [--quiet] <indicators.jsonl>
          utoaegis history list --history <path> [--limit <1-200>] [--json]
          utoaegis history show --history <path> [--json] <scan-id>
          utoaegis history prune --history <path> --older-than-days <1-36500> [--json]
          utoaegis updates apply --store <path> --trusted-key <key-id>=<public-key.pem> [--json] <bundle-directory>
          utoaegis updates status --store <path> [--json]
          utoaegis updates rollback --store <path> --trusted-key <key-id>=<public-key.pem> [--json]

        Commands:
          scan            Calculate SHA-256 and optionally run reputation and signature checks.
          scan-directory  Scan each regular file in a directory without following reparse points.
          monitor         Watch a directory and scan changed files until Ctrl+C is pressed.
          quarantine add  Scan and quarantine a file only when a configured detector matches.
          quarantine list List recent entries in a restricted quarantine vault.
          quarantine show Show one quarantine entry and its detection evidence.
          quarantine restore  Restore an entry without overwriting an existing file.
          import-hashes   Validate and transactionally import JSON Lines indicators.
          history list    List recent stored scan summaries, newest first.
          history show    Show one complete stored scan record.
          history prune   Delete records older than the configured retention age.
          updates apply   Verify, stage, and atomically activate a signed threat bundle.
          updates status  Show active, rollback, and anti-rollback sequence state.
          updates rollback  Reverify and restore the last known-good content version.

        Options:
          --recursive        Include nested directories; disabled by default.
          --max-concurrency  Concurrent files in directory and recovery scans; default 4, maximum 32.
          --debounce-ms      Quiet period before scanning a changed file; default 500, maximum 60000.
          --queue-capacity   Maximum queued file events; default 4096, maximum 65536.
          --database         SQLite reputation database path.
          --signatures       JSON Lines exact-byte signature rule file.
          --history          Separate SQLite database for opt-in scan history.
          --vault            Restricted quarantine vault directory.
          --destination      Optional nonexisting path for quarantine restore.
          --limit            Maximum history summaries to list; default 25, maximum 200.
          --older-than-days  Delete history older than this many days.
          --store            Managed threat-content store directory.
          --trusted-key      Trusted ECDSA P-256 key as <key-id>=<public-key.pem>; repeatable.
          --json             Emit the result as JSON.
          --quiet            Suppress structured operational logs on stderr.
          --                 Treat all following arguments as positional values.
          -h, --help         Show this help text.

        JSON Lines indicator fields:
          sha256, source, optional classification (Malware), malwareFamily,
          and firstSeenUtc.

        JSON Lines signature fields:
          id, name, source, and hexPattern (8 to 1024 bytes; no separators).
        """);
}
