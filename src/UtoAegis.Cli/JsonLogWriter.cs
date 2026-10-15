using System.Text.Json;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Cli;

internal static class JsonLogWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static void ScanStarted(string path) => Write(
        "information", "hash_scan_started", path, null, null);

    public static void ScanFinished(
        FileHashScanResult result,
        HashReputationResult? reputation) => Write(
        result.IsSuccess ? "information" : "warning",
        result.IsSuccess ? "hash_scan_completed" : "hash_scan_failed",
        result.Path,
        result.Status.ToString(),
        result.Elapsed.TotalMilliseconds,
        reputation?.Status.ToString());

    public static void ImportFinished(
        string databasePath,
        HashImportResult result,
        int duplicateCount)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "hash_import_completed",
            databasePath = Path.GetFullPath(databasePath),
            result.ProcessedCount,
            result.ChangedCount,
            result.UnchangedCount,
            duplicateCount
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void SignatureRulesLoaded(
        string rulePath,
        int ruleCount,
        int duplicateCount)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "signature_rules_loaded",
            rulePath = Path.GetFullPath(rulePath),
            ruleCount,
            duplicateCount
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void SignatureScanFinished(SignatureScanResult result) => Write(
        result.IsCompleted ? "information" : "warning",
        result.IsCompleted ? "signature_scan_completed" : "signature_scan_failed",
        result.Path,
        result.Status.ToString(),
        result.Elapsed.TotalMilliseconds);

    public static void DirectoryScanStarted(
        string path,
        bool recursive,
        int maximumConcurrency)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "directory_scan_started",
            path,
            recursive,
            maximumConcurrency
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void DirectoryScanFinished(DirectoryScanResult result)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = result.Status == DirectoryScanStatus.Completed ? "information" : "warning",
            eventName = result.IsCompleted
                ? "directory_scan_completed"
                : "directory_scan_failed",
            path = result.RootPath,
            status = result.Status.ToString(),
            elapsedMilliseconds = result.Elapsed.TotalMilliseconds,
            fileCount = result.Files.Count,
            detectedFileCount = result.DetectedFileCount,
            failedFileCount = result.FailedFileCount,
            issueCount = result.Issues.Count
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    private static void Write(
        string level,
        string eventName,
        string? path,
        string? status,
        double? elapsedMilliseconds,
        string? reputationStatus = null)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level,
            eventName,
            path,
            status,
            elapsedMilliseconds,
            reputationStatus
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }
}
