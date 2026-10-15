using System.Text.Json;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Cli;

internal static class JsonLogWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static void ScanStarted(Guid scanId, string path) => Write(
        scanId, "information", "hash_scan_started", path, null, null);

    public static void ScanFinished(
        Guid scanId,
        FileHashScanResult result,
        HashReputationResult? reputation) => Write(
        scanId,
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
        Guid scanId,
        string rulePath,
        int ruleCount,
        int duplicateCount)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "signature_rules_loaded",
            scanId,
            rulePath = Path.GetFullPath(rulePath),
            ruleCount,
            duplicateCount
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void SignatureScanFinished(Guid scanId, SignatureScanResult result) => Write(
        scanId,
        result.IsCompleted ? "information" : "warning",
        result.IsCompleted ? "signature_scan_completed" : "signature_scan_failed",
        result.Path,
        result.Status.ToString(),
        result.Elapsed.TotalMilliseconds);

    public static void DirectoryScanStarted(
        Guid scanId,
        string path,
        bool recursive,
        int maximumConcurrency)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "directory_scan_started",
            scanId,
            path,
            recursive,
            maximumConcurrency
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void DirectoryScanFinished(Guid scanId, DirectoryScanResult result)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = result.Status == DirectoryScanStatus.Completed ? "information" : "warning",
            eventName = result.IsCompleted
                ? "directory_scan_completed"
                : "directory_scan_failed",
            scanId,
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

    public static void HistoryStored(ScanHistoryRecord record, string databasePath)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "scan_history_stored",
            scanId = record.Id,
            databasePath = Path.GetFullPath(databasePath),
            outcome = record.Outcome.ToString(),
            fileCount = record.Files.Count,
            detectedFileCount = record.DetectedFileCount,
            issueCount = record.Issues.Count
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void HistoryStoreFailed(Guid scanId, string databasePath, string message)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "error",
            eventName = "scan_history_store_failed",
            scanId,
            databasePath = Path.GetFullPath(databasePath),
            message
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorStarted(
        Guid sessionId,
        string rootPath,
        bool recursive,
        int debounceMilliseconds,
        int queueCapacity)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "file_monitor_started",
            sessionId,
            rootPath,
            recursive,
            debounceMilliseconds,
            queueCapacity
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorFileScanned(
        Guid sessionId,
        Guid scanId,
        FileMonitorScanResult result)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = result.Result.IsCompleted ? "information" : "warning",
            eventName = "monitored_file_scanned",
            sessionId,
            scanId,
            path = result.Path,
            changeKind = result.ChangeKind.ToString(),
            detected = result.Result.IsDetected,
            completed = result.Result.IsCompleted
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorRecoveryCompleted(
        Guid sessionId,
        Guid scanId,
        FileMonitorRecoveryResult result)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = result.Result.Status == DirectoryScanStatus.Completed
                ? "information"
                : "warning",
            eventName = "monitor_recovery_scan_completed",
            sessionId,
            scanId,
            reason = result.Reason.ToString(),
            status = result.Result.Status.ToString(),
            fileCount = result.Result.Files.Count,
            detectedFileCount = result.Result.DetectedFileCount,
            failedFileCount = result.Result.FailedFileCount,
            issueCount = result.Result.Issues.Count
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorIssue(Guid sessionId, FileMonitorIssue issue)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "warning",
            eventName = "file_monitor_issue",
            sessionId,
            kind = issue.Kind.ToString(),
            path = issue.Path,
            issue.Message,
            issue.ObservedUtc
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorStopped(Guid sessionId, FileMonitorSummary summary)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "file_monitor_stopped",
            sessionId,
            summary.EventCount,
            summary.FileScanCount,
            summary.RecoveryScanCount,
            summary.IssueCount,
            elapsedMilliseconds = summary.Elapsed.TotalMilliseconds
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    public static void MonitorCancelled(Guid sessionId)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = "information",
            eventName = "file_monitor_cancelled",
            sessionId
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }

    private static void Write(
        Guid scanId,
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
            scanId,
            path,
            status,
            elapsedMilliseconds,
            reputationStatus
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }
}
