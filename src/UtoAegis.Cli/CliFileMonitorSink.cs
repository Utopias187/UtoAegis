using System.Text.Json;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;

namespace UtoAegis.Cli;

internal sealed class CliFileMonitorSink : IFileMonitorSink
{
    private static readonly JsonSerializerOptions StreamJsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly Guid _sessionId;
    private readonly CliOptions _options;
    private readonly IScanHistoryStore? _historyStore;

    public CliFileMonitorSink(
        Guid sessionId,
        CliOptions options,
        IScanHistoryStore? historyStore)
    {
        _sessionId = sessionId;
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _historyStore = historyStore;
    }

    public bool HasDetections { get; private set; }

    public bool HistoryWriteFailed { get; private set; }

    public async ValueTask FileScannedAsync(
        FileMonitorScanResult result,
        CancellationToken cancellationToken = default)
    {
        var scanId = Guid.NewGuid();
        HasDetections |= result.Result.IsDetected;
        var record = ScanHistoryRecord.FromFileScan(
            scanId,
            result.Path,
            result.StartedUtc,
            result.CompletedUtc,
            result.Result);
        await PersistAsync(record, cancellationToken);

        if (!_options.Quiet)
        {
            JsonLogWriter.MonitorFileScanned(_sessionId, scanId, result);
        }

        if (_options.Json)
        {
            WriteJson(new
            {
                eventType = "fileScan",
                sessionId = _sessionId,
                scanId,
                path = result.Path,
                changeKind = result.ChangeKind.ToString(),
                observedUtc = result.ObservedUtc,
                startedUtc = result.StartedUtc,
                completedUtc = result.CompletedUtc,
                detected = result.Result.IsDetected,
                completed = result.Result.IsCompleted,
                hashStatus = result.Result.FileHash.Status.ToString(),
                sha256 = result.Result.FileHash.Sha256,
                reputationStatus = result.Result.Reputation?.Status.ToString(),
                signatureStatus = result.Result.Signatures?.Status.ToString(),
                signatureMatches = result.Result.Signatures?.Matches.Select(match => new
                {
                    match.RuleId,
                    match.RuleName,
                    match.Source,
                    match.Offset,
                    match.PatternLengthBytes
                })
            });
            return;
        }

        var label = result.Result.IsDetected
            ? "DETECTED"
            : result.Result.IsCompleted
                ? "NO DETECTION"
                : "FAILED";
        Console.WriteLine(
            $"[{label}] {result.ChangeKind} {result.Path} (scan {scanId:D})");
    }

    public async ValueTask RecoveryScanCompletedAsync(
        FileMonitorRecoveryResult result,
        CancellationToken cancellationToken = default)
    {
        var scanId = Guid.NewGuid();
        HasDetections |= result.Result.HasDetections;
        var record = ScanHistoryRecord.FromDirectoryScan(
            scanId,
            result.Result.RootPath ?? _options.InputPath!,
            _options.Recursive,
            result.StartedUtc,
            result.CompletedUtc,
            result.Result);
        await PersistAsync(record, cancellationToken);

        if (!_options.Quiet)
        {
            JsonLogWriter.MonitorRecoveryCompleted(_sessionId, scanId, result);
        }

        if (_options.Json)
        {
            WriteJson(new
            {
                eventType = "recoveryScan",
                sessionId = _sessionId,
                scanId,
                reason = result.Reason.ToString(),
                status = result.Result.Status.ToString(),
                rootPath = result.Result.RootPath,
                startedUtc = result.StartedUtc,
                completedUtc = result.CompletedUtc,
                fileCount = result.Result.Files.Count,
                detectedFileCount = result.Result.DetectedFileCount,
                failedFileCount = result.Result.FailedFileCount,
                issueCount = result.Result.Issues.Count,
                error = result.Result.ErrorMessage
            });
            return;
        }

        Console.WriteLine(
            $"[RECOVERY {result.Reason}] {result.Result.Status}: " +
            $"{result.Result.Files.Count} file(s), " +
            $"{result.Result.DetectedFileCount} detection(s), " +
            $"{result.Result.Issues.Count} issue(s) (scan {scanId:D})");
    }

    public ValueTask IssueAsync(
        FileMonitorIssue issue,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_options.Quiet)
        {
            JsonLogWriter.MonitorIssue(_sessionId, issue);
        }

        if (_options.Json)
        {
            WriteJson(new
            {
                eventType = "monitorIssue",
                sessionId = _sessionId,
                kind = issue.Kind.ToString(),
                path = issue.Path,
                message = issue.Message,
                observedUtc = issue.ObservedUtc
            });
        }
        else
        {
            Console.Error.WriteLine($"[{issue.Kind}] {issue.Path}: {issue.Message}");
        }

        return ValueTask.CompletedTask;
    }

    private async ValueTask PersistAsync(
        ScanHistoryRecord record,
        CancellationToken cancellationToken)
    {
        if (_historyStore is null || _options.HistoryPath is null)
        {
            return;
        }

        try
        {
            await _historyStore.AppendAsync(record, cancellationToken);
            if (!_options.Quiet)
            {
                JsonLogWriter.HistoryStored(record, _options.HistoryPath);
            }
        }
        catch (ScanHistoryStoreException exception)
        {
            HistoryWriteFailed = true;
            Console.Error.WriteLine(
                $"Monitor scan completed, but history storage failed: {exception.Message}");
            if (!_options.Quiet)
            {
                JsonLogWriter.HistoryStoreFailed(
                    record.Id,
                    _options.HistoryPath,
                    exception.Message);
            }
        }
    }

    private static void WriteJson<T>(T value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, StreamJsonOptions));
}
