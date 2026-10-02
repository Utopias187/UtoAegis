using System.Text.Json;
using UtoAegis.Cli;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Infrastructure.Importing;
using UtoAegis.Infrastructure.Reputation;

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
catch (ReputationStoreException exception)
{
    Console.Error.WriteLine($"Reputation database error: {exception.Message}");
    return ExitCodes.ImportFailed;
}
catch (UnauthorizedAccessException)
{
    Console.Error.WriteLine("The operation was denied by the file system.");
    return ExitCodes.ImportFailed;
}
catch (IOException)
{
    Console.Error.WriteLine("The operation failed because a file could not be read or written.");
    return ExitCodes.ImportFailed;
}

static async Task<int> RunScanAsync(CliOptions options, CancellationToken cancellationToken)
{
    if (!options.Quiet)
    {
        JsonLogWriter.ScanStarted(options.InputPath!);
    }

    var hashScanner = new Sha256FileHashScanner();
    FileHashScanResult hashResult;
    HashReputationResult? reputation = null;

    if (options.DatabasePath is null)
    {
        hashResult = await hashScanner.ScanAsync(options.InputPath!, cancellationToken);
    }
    else
    {
        var store = new SqliteHashReputationStore(options.DatabasePath);
        await store.InitializeAsync(cancellationToken);
        var scanner = new FileReputationScanner(hashScanner, store);
        var result = await scanner.ScanAsync(options.InputPath!, cancellationToken);
        hashResult = result.FileHash;
        reputation = result.Reputation;
    }

    if (!options.Quiet)
    {
        JsonLogWriter.ScanFinished(hashResult, reputation);
    }

    WriteScanResult(options.Json, hashResult, reputation);

    if (!hashResult.IsSuccess)
    {
        return ExitCodes.ScanFailed;
    }

    return reputation?.Status switch
    {
        HashReputationStatus.Malicious => ExitCodes.ThreatDetected,
        HashReputationStatus.LookupFailed => ExitCodes.ReputationLookupFailed,
        _ => ExitCodes.Success
    };
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
    FileHashScanResult hashResult,
    HashReputationResult? reputation)
{
    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
                status = hashResult.Status.ToString(),
                path = hashResult.Path,
                algorithm = hashResult.IsSuccess ? "SHA-256" : null,
                sha256 = hashResult.Sha256,
                fileSizeBytes = hashResult.FileSizeBytes,
                elapsedMilliseconds = hashResult.Elapsed.TotalMilliseconds,
                error = hashResult.ErrorMessage,
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
                    }
            },
            CliJson.ResultOptions));
        return;
    }

    if (!hashResult.IsSuccess)
    {
        Console.Error.WriteLine($"Scan failed ({hashResult.Status}): {hashResult.ErrorMessage}");
        return;
    }

    Console.WriteLine($"{hashResult.Sha256}  {hashResult.Path}");

    if (reputation?.Status == HashReputationStatus.Malicious)
    {
        var family = reputation.Indicator!.MalwareFamily ?? "unspecified family";
        Console.WriteLine(
            $"Reputation: MALICIOUS ({family}; source: {reputation.Indicator.Source})");
    }
    else if (reputation?.Status == HashReputationStatus.Unknown)
    {
        Console.WriteLine("Reputation: UNKNOWN (not present in the configured database)");
    }
    else if (reputation?.Status == HashReputationStatus.LookupFailed)
    {
        Console.Error.WriteLine($"Reputation lookup failed: {reputation.ErrorMessage}");
    }
}

static void PrintUsage()
{
    Console.WriteLine(
        """
        UtoAegis file and hash-reputation scanner

        Usage:
          utoaegis [scan] [--database <path>] [--json] [--quiet] [--] <file>
          utoaegis import-hashes --database <path> [--json] [--quiet] <indicators.jsonl>

        Commands:
          scan           Calculate SHA-256 and optionally query a reputation database.
          import-hashes  Validate and transactionally import JSON Lines indicators.

        Options:
          --database     SQLite reputation database path.
          --json         Emit the result as JSON.
          --quiet        Suppress structured operational logs on stderr.
          --             Treat all following arguments as positional values.
          -h, --help     Show this help text.

        JSON Lines indicator fields:
          sha256, source, optional classification (Malware), malwareFamily,
          and firstSeenUtc.
        """);
}
