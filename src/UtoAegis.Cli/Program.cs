using System.Text.Json;
using UtoAegis.Cli;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;
using UtoAegis.Infrastructure.Importing;
using UtoAegis.Infrastructure.Reputation;
using UtoAegis.Infrastructure.Signatures;

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
        CliCommand.ImportHashes => await RunImportAsync(options, cancellation.Token),
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
    if (!options.Quiet)
    {
        JsonLogWriter.ScanStarted(options.InputPath!);
    }

    var scanner = await CreateFileScannerAsync(options, cancellationToken);
    var result = await scanner.ScanAsync(options.InputPath!, cancellationToken);

    if (!options.Quiet)
    {
        JsonLogWriter.ScanFinished(result.FileHash, result.Reputation);
        if (result.Signatures is not null)
        {
            JsonLogWriter.SignatureScanFinished(result.Signatures);
        }
    }

    WriteScanResult(options.Json, result);
    return ExitCodeResolver.ForFile(result);
}

static async Task<int> RunDirectoryScanAsync(
    CliOptions options,
    CancellationToken cancellationToken)
{
    if (!options.Quiet)
    {
        JsonLogWriter.DirectoryScanStarted(
            options.InputPath!,
            options.Recursive,
            options.MaximumConcurrency);
    }

    var fileScanner = await CreateFileScannerAsync(options, cancellationToken);
    var directoryScanner = new DirectoryScanner(
        fileScanner,
        new DirectoryScanOptions(
            recurse: options.Recursive,
            maximumConcurrency: options.MaximumConcurrency,
            excludedPaths: DirectoryScanExclusions(options)));
    var result = await directoryScanner.ScanAsync(options.InputPath!, cancellationToken);

    if (!options.Quiet)
    {
        JsonLogWriter.DirectoryScanFinished(result);
    }

    WriteDirectoryScanResult(options.Json, options, result);
    return ExitCodeResolver.ForDirectory(result);
}

static async ValueTask<IFileScanner> CreateFileScannerAsync(
    CliOptions options,
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

static void WriteScanResult(bool json, FileScanResult result)
{
    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            CreateFileScanPayload(result),
            CliJson.ResultOptions));
        return;
    }

    WriteHumanFileDetails(result);
}

static void WriteDirectoryScanResult(
    bool json,
    CliOptions options,
    DirectoryScanResult result)
{
    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
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
        UtoAegis file, directory, hash-reputation, and signature scanner

        Usage:
          utoaegis [scan] [--database <path>] [--signatures <path>] [--json] [--quiet] [--] <file>
          utoaegis scan-directory [--recursive] [--max-concurrency <1-32>] [--database <path>] [--signatures <path>] [--json] [--quiet] [--] <directory>
          utoaegis import-hashes --database <path> [--json] [--quiet] <indicators.jsonl>

        Commands:
          scan            Calculate SHA-256 and optionally run reputation and signature checks.
          scan-directory  Scan each regular file in a directory without following reparse points.
          import-hashes   Validate and transactionally import JSON Lines indicators.

        Options:
          --recursive        Include nested directories; disabled by default.
          --max-concurrency  Concurrent file scans for scan-directory; default 4, maximum 32.
          --database         SQLite reputation database path.
          --signatures       JSON Lines exact-byte signature rule file.
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
