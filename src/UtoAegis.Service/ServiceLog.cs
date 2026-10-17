using Microsoft.Extensions.Logging;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Service;

internal static partial class ServiceLog
{
    [LoggerMessage(
        EventId = 100,
        Level = LogLevel.Information,
        Message = "UtoAegis monitoring started for {MonitorRoot} in {ResponseMode} mode.")]
    public static partial void MonitoringStarted(
        ILogger logger,
        string monitorRoot,
        ResponseMode responseMode);

    [LoggerMessage(
        EventId = 101,
        Level = LogLevel.Information,
        Message = "Loaded {RuleCount} signature rules; ignored {DuplicateCount} duplicates.")]
    public static partial void SignatureRulesLoaded(
        ILogger logger,
        int ruleCount,
        int duplicateCount);

    [LoggerMessage(
        EventId = 102,
        Level = LogLevel.Information,
        Message = "Health: scanned={Scanned}, detections={Detections}, quarantined={Quarantined}, responseFailures={ResponseFailures}, monitorIssues={MonitorIssues}, historyFailures={HistoryFailures}.")]
    public static partial void Health(
        ILogger logger,
        long scanned,
        long detections,
        long quarantined,
        long responseFailures,
        long monitorIssues,
        long historyFailures);

    [LoggerMessage(
        EventId = 103,
        Level = LogLevel.Information,
        Message = "Monitoring stopped after {ElapsedMilliseconds} ms: events={Events}, fileScans={FileScans}, recoveryScans={RecoveryScans}, issues={Issues}.")]
    public static partial void MonitoringStopped(
        ILogger logger,
        double elapsedMilliseconds,
        long events,
        long fileScans,
        long recoveryScans,
        long issues);

    [LoggerMessage(
        EventId = 104,
        Level = LogLevel.Information,
        Message = "Loaded authenticated threat content {Version} at sequence {Sequence} using key {KeyId}; expires {ExpiresUtc}.")]
    public static partial void ThreatContentLoaded(
        ILogger logger,
        string version,
        long sequence,
        string keyId,
        DateTimeOffset expiresUtc);

    [LoggerMessage(
        EventId = 200,
        Level = LogLevel.Debug,
        Message = "Scanned {Path}; completed={Completed}, detected={Detected}.")]
    public static partial void FileScanned(
        ILogger logger,
        string path,
        bool completed,
        bool detected);

    [LoggerMessage(
        EventId = 201,
        Level = LogLevel.Information,
        Message = "Recovery scan {Reason} completed: status={Status}, files={Files}, detections={Detections}, issues={Issues}.")]
    public static partial void RecoveryScanCompleted(
        ILogger logger,
        MonitorRecoveryReason reason,
        DirectoryScanStatus status,
        int files,
        int detections,
        int issues);

    [LoggerMessage(
        EventId = 300,
        Level = LogLevel.Warning,
        Message = "Detection response for {Path}: {Decision}. {Reason}")]
    public static partial void DetectionResponse(
        ILogger logger,
        string path,
        ResponseDecisionKind decision,
        string reason);

    [LoggerMessage(
        EventId = 301,
        Level = LogLevel.Warning,
        Message = "Monitor issue {Kind} for {Path}: {Message}")]
    public static partial void MonitorIssue(
        ILogger logger,
        FileMonitorIssueKind kind,
        string? path,
        string message);

    [LoggerMessage(
        EventId = 302,
        Level = LogLevel.Warning,
        Message = "Active authenticated threat content {Version} expired at {ExpiresUtc}; continuing with the last known-good version.")]
    public static partial void ThreatContentExpired(
        ILogger logger,
        string version,
        DateTimeOffset expiresUtc);

    [LoggerMessage(
        EventId = 400,
        Level = LogLevel.Error,
        Message = "Scan history persistence failed.")]
    public static partial void HistoryFailed(ILogger logger, Exception exception);
}
