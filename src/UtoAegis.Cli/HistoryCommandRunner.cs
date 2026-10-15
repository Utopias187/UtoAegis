using System.Text.Json;
using UtoAegis.Core.History;
using UtoAegis.Infrastructure.History;

namespace UtoAegis.Cli;

internal static class HistoryCommandRunner
{
    public static async Task<int> ListAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = await OpenStoreAsync(options.HistoryPath!, cancellationToken);
        var summaries = await store.ListAsync(options.HistoryLimit, cancellationToken);

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    databasePath = Path.GetFullPath(options.HistoryPath!),
                    count = summaries.Count,
                    scans = summaries.Select(summary => new
                    {
                        scanId = summary.Id,
                        targetKind = summary.TargetKind.ToString(),
                        targetPath = summary.TargetPath,
                        recursive = summary.Recursive,
                        startedUtc = summary.StartedUtc,
                        completedUtc = summary.CompletedUtc,
                        outcome = summary.Outcome.ToString(),
                        fileCount = summary.FileCount,
                        detectedFileCount = summary.DetectedFileCount,
                        failedFileCount = summary.FailedFileCount,
                        issueCount = summary.IssueCount,
                        error = summary.ErrorMessage
                    })
                },
                CliJson.ResultOptions));
            return ExitCodes.Success;
        }

        if (summaries.Count == 0)
        {
            Console.WriteLine("No scan history records found.");
            return ExitCodes.Success;
        }

        foreach (var summary in summaries)
        {
            Console.WriteLine(
                $"{summary.CompletedUtc:O}  {summary.Id:D}  {summary.Outcome}  " +
                $"files={summary.FileCount} detected={summary.DetectedFileCount} " +
                $"failed={summary.FailedFileCount}  {summary.TargetPath}");
        }

        return ExitCodes.Success;
    }

    public static async Task<int> ShowAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = await OpenStoreAsync(options.HistoryPath!, cancellationToken);
        var scanId = Guid.ParseExact(options.InputPath!, "D");
        var record = await store.GetAsync(scanId, cancellationToken);
        if (record is null)
        {
            Console.Error.WriteLine($"No history record exists for scan {scanId:D}.");
            return ExitCodes.HistoryStoreFailed;
        }

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                CreateRecordPayload(record),
                CliJson.ResultOptions));
            return ExitCodes.Success;
        }

        Console.WriteLine($"Scan ID: {record.Id:D}");
        Console.WriteLine($"Target: {record.TargetKind} {record.TargetPath}");
        Console.WriteLine($"Started: {record.StartedUtc:O}");
        Console.WriteLine($"Completed: {record.CompletedUtc:O}");
        Console.WriteLine($"Outcome: {record.Outcome}");
        Console.WriteLine(
            $"Summary: {record.Files.Count} file(s), {record.DetectedFileCount} detection(s), " +
            $"{record.FailedFileCount} failure(s), {record.Issues.Count} issue(s)");

        foreach (var file in record.Files)
        {
            var label = file.Detected ? "DETECTED" : file.Completed ? "NO DETECTION" : "FAILED";
            Console.WriteLine($"[{label}] {file.Path}");
            foreach (var match in file.SignatureMatches)
            {
                Console.WriteLine(
                    $"  {match.RuleId} at byte {match.Offset} " +
                    $"({match.RuleName}; source: {match.Source})");
            }
        }

        foreach (var issue in record.Issues)
        {
            Console.Error.WriteLine($"[{issue.Kind}] {issue.Path}: {issue.Message}");
        }

        return ExitCodes.Success;
    }

    public static async Task<int> PruneAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var store = await OpenStoreAsync(options.HistoryPath!, cancellationToken);
        var cutoffUtc = DateTimeOffset.UtcNow.AddDays(-options.OlderThanDays!.Value);
        var result = await store.PruneAsync(cutoffUtc, cancellationToken);

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    status = "Pruned",
                    databasePath = Path.GetFullPath(options.HistoryPath!),
                    cutoffUtc,
                    result.DeletedScanCount
                },
                CliJson.ResultOptions));
        }
        else
        {
            Console.WriteLine(
                $"Deleted {result.DeletedScanCount} scan history record(s) completed before " +
                $"{cutoffUtc:O}.");
        }

        return ExitCodes.Success;
    }

    private static async ValueTask<IScanHistoryStore> OpenStoreAsync(
        string path,
        CancellationToken cancellationToken)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ScanHistoryStoreException(
                "The history database path is invalid.",
                exception);
        }

        if (!File.Exists(fullPath))
        {
            throw new ScanHistoryStoreException(
                "The scan history database does not exist. Run a scan with --history first.");
        }

        var store = new SqliteScanHistoryStore(fullPath);
        await store.InitializeAsync(cancellationToken);
        return store;
    }

    private static object CreateRecordPayload(ScanHistoryRecord record) => new
    {
        scanId = record.Id,
        targetKind = record.TargetKind.ToString(),
        targetPath = record.TargetPath,
        recursive = record.Recursive,
        startedUtc = record.StartedUtc,
        completedUtc = record.CompletedUtc,
        elapsedMilliseconds = (record.CompletedUtc - record.StartedUtc).TotalMilliseconds,
        outcome = record.Outcome.ToString(),
        error = record.ErrorMessage,
        summary = new
        {
            fileCount = record.Files.Count,
            detectedFileCount = record.DetectedFileCount,
            failedFileCount = record.FailedFileCount,
            issueCount = record.Issues.Count
        },
        issues = record.Issues.Select(issue => new
        {
            path = issue.Path,
            kind = issue.Kind.ToString(),
            message = issue.Message
        }),
        files = record.Files.Select(file => new
        {
            path = file.Path,
            hashStatus = file.HashStatus.ToString(),
            file.Sha256,
            file.FileSizeBytes,
            file.Detected,
            file.Completed,
            reputationStatus = file.ReputationStatus?.ToString(),
            reputationClassification = file.ReputationClassification?.ToString(),
            file.ReputationMalwareFamily,
            file.ReputationSource,
            file.ReputationFirstSeenUtc,
            signatureStatus = file.SignatureStatus?.ToString(),
            file.SignatureEngine,
            signatureMatches = file.SignatureMatches.Select(match => new
            {
                match.RuleId,
                match.RuleName,
                match.Source,
                match.Offset,
                match.PatternLengthBytes
            }),
            file.HashError,
            file.ReputationError,
            file.SignatureError
        })
    };
}
