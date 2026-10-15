using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Monitoring;

public sealed class FileMonitoringEngine
{
    private readonly IFileScanner _fileScanner;
    private readonly IDirectoryScanner _directoryScanner;
    private readonly IFileMonitorSink _sink;
    private readonly FileMonitorOptions _options;
    private readonly TimeProvider _timeProvider;

    public FileMonitoringEngine(
        IFileScanner fileScanner,
        IDirectoryScanner directoryScanner,
        IFileMonitorSink sink,
        FileMonitorOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _fileScanner = fileScanner ?? throw new ArgumentNullException(nameof(fileScanner));
        _directoryScanner = directoryScanner ?? throw new ArgumentNullException(nameof(directoryScanner));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _options = options ?? new FileMonitorOptions();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<FileMonitorSummary> RunAsync(
        string rootPath,
        IFileMonitorEventSource eventSource,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentNullException.ThrowIfNull(eventSource);

        var normalizedRoot = Path.GetFullPath(rootPath);
        var startedTimestamp = _timeProvider.GetTimestamp();
        long eventCount = 0;
        long fileScanCount = 0;
        long recoveryScanCount = 0;
        long issueCount = 0;
        var pending = new Dictionary<string, PendingFileChange>(PathComparer);

        if (_options.RunInitialScan)
        {
            await RunRecoveryScanAsync(
                normalizedRoot,
                MonitorRecoveryReason.InitialScan,
                cancellationToken);
            recoveryScanCount++;
        }

        await using var enumerator = eventSource
            .ReadAllAsync(cancellationToken)
            .GetAsyncEnumerator(cancellationToken);
        Task<bool>? moveNext = enumerator.MoveNextAsync().AsTask();
        var sourceCompleted = false;

        while (!sourceCompleted || pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var delay = DelayUntilNextPendingAsync(pending, cancellationToken);

            if (!sourceCompleted && moveNext is not null)
            {
                var completed = pending.Count == 0
                    ? moveNext
                    : await Task.WhenAny(moveNext, delay).ConfigureAwait(false);
                if (completed == moveNext)
                {
                    if (!await moveNext.ConfigureAwait(false))
                    {
                        sourceCompleted = true;
                        moveNext = null;
                        continue;
                    }

                    var monitorEvent = enumerator.Current;
                    eventCount++;
                    if (monitorEvent.Kind == FileMonitorEventKind.FileChanged)
                    {
                        AddPending(pending, monitorEvent);
                    }
                    else if (monitorEvent.Kind == FileMonitorEventKind.Overflow)
                    {
                        pending.Clear();
                        await ReportIssueAsync(
                            new FileMonitorIssue(
                                FileMonitorIssueKind.EventOverflow,
                                null,
                                monitorEvent.Message ?? "The file event stream overflowed.",
                                monitorEvent.ObservedUtc),
                            cancellationToken);
                        issueCount++;
                        await RunRecoveryScanAsync(
                            normalizedRoot,
                            MonitorRecoveryReason.EventOverflow,
                            cancellationToken);
                        recoveryScanCount++;
                    }
                    else
                    {
                        await ReportIssueAsync(
                            new FileMonitorIssue(
                                FileMonitorIssueKind.SourceError,
                                null,
                                monitorEvent.Message ?? "The file event source reported an error.",
                                monitorEvent.ObservedUtc),
                            cancellationToken);
                        issueCount++;
                    }

                    moveNext = enumerator.MoveNextAsync().AsTask();
                    continue;
                }
            }

            await delay.ConfigureAwait(false);
            foreach (var change in ReadyChanges(pending))
            {
                var issue = ValidateFile(normalizedRoot, change.Path, change.ObservedUtc);
                if (issue is not null)
                {
                    await ReportIssueAsync(issue, cancellationToken);
                    issueCount++;
                    continue;
                }

                var result = await _fileScanner
                    .ScanAsync(change.Path, cancellationToken)
                    .ConfigureAwait(false);
                await _sink.FileScannedAsync(
                    new FileMonitorScanResult(
                        change.Path,
                        change.ChangeKind,
                        change.ObservedUtc,
                        _timeProvider.GetUtcNow(),
                        result),
                    cancellationToken);
                fileScanCount++;
            }
        }

        return new FileMonitorSummary(
            eventCount,
            fileScanCount,
            recoveryScanCount,
            issueCount,
            _timeProvider.GetElapsedTime(startedTimestamp));
    }

    private async ValueTask RunRecoveryScanAsync(
        string rootPath,
        MonitorRecoveryReason reason,
        CancellationToken cancellationToken)
    {
        var startedUtc = _timeProvider.GetUtcNow();
        var result = await _directoryScanner
            .ScanAsync(rootPath, cancellationToken)
            .ConfigureAwait(false);
        await _sink.RecoveryScanCompletedAsync(
            new FileMonitorRecoveryResult(
                reason,
                startedUtc,
                _timeProvider.GetUtcNow(),
                result),
            cancellationToken);
    }

    private void AddPending(
        IDictionary<string, PendingFileChange> pending,
        FileMonitorEvent monitorEvent)
    {
        var path = monitorEvent.Path!;
        pending[path] = new PendingFileChange(
            path,
            monitorEvent.ChangeKind!.Value,
            monitorEvent.ObservedUtc,
            _timeProvider.GetUtcNow() + _options.DebounceDelay);
    }

    private Task DelayUntilNextPendingAsync(
        IReadOnlyDictionary<string, PendingFileChange> pending,
        CancellationToken cancellationToken)
    {
        if (pending.Count == 0)
        {
            return Task.Delay(Timeout.InfiniteTimeSpan, _timeProvider, cancellationToken);
        }

        var delay = pending.Values.Min(change => change.DueUtc) - _timeProvider.GetUtcNow();
        return delay <= TimeSpan.Zero
            ? Task.CompletedTask
            : Task.Delay(delay, _timeProvider, cancellationToken);
    }

    private PendingFileChange[] ReadyChanges(
        IDictionary<string, PendingFileChange> pending)
    {
        var now = _timeProvider.GetUtcNow();
        var ready = pending.Values
            .Where(change => change.DueUtc <= now)
            .OrderBy(change => change.Path, StringComparer.Ordinal)
            .ToArray();
        foreach (var change in ready)
        {
            pending.Remove(change.Path);
        }

        return ready;
    }

    private static FileMonitorIssue? ValidateFile(
        string rootPath,
        string candidatePath,
        DateTimeOffset observedUtc)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(candidatePath);
            var relativePath = Path.GetRelativePath(rootPath, fullPath);
            if (Path.IsPathRooted(relativePath) ||
                relativePath == ".." ||
                relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
                relativePath.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
            {
                return new FileMonitorIssue(
                    FileMonitorIssueKind.OutsideRoot,
                    candidatePath,
                    "The event path is outside the monitored root.",
                    observedUtc);
            }

            var rootAttributes = File.GetAttributes(rootPath);
            if ((rootAttributes & FileAttributes.ReparsePoint) != 0)
            {
                return ReparseIssue(rootPath, observedUtc);
            }

            var current = rootPath;
            var segments = relativePath.Split(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                StringSplitOptions.RemoveEmptyEntries);
            for (var index = 0; index < segments.Length - 1; index++)
            {
                current = Path.Combine(current, segments[index]);
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return ReparseIssue(current, observedUtc);
                }
            }

            var fileAttributes = File.GetAttributes(fullPath);
            if ((fileAttributes & FileAttributes.ReparsePoint) != 0)
            {
                return ReparseIssue(fullPath, observedUtc);
            }

            if ((fileAttributes & FileAttributes.Directory) != 0)
            {
                return new FileMonitorIssue(
                    FileMonitorIssueKind.NotARegularFile,
                    fullPath,
                    "The changed entry is not a regular file.",
                    observedUtc);
            }

            return null;
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new FileMonitorIssue(
                FileMonitorIssueKind.OutsideRoot,
                candidatePath,
                "The event path is invalid.",
                observedUtc);
        }
        catch (Exception exception) when (
            exception is FileNotFoundException or DirectoryNotFoundException or
                UnauthorizedAccessException or IOException)
        {
            return new FileMonitorIssue(
                FileMonitorIssueKind.EntryUnavailable,
                candidatePath,
                "The changed entry was unavailable when its debounce period ended.",
                observedUtc);
        }
    }

    private static FileMonitorIssue ReparseIssue(string path, DateTimeOffset observedUtc) =>
        new(
            FileMonitorIssueKind.ReparsePointSkipped,
            path,
            "A reparse point was not followed.",
            observedUtc);

    private ValueTask ReportIssueAsync(
        FileMonitorIssue issue,
        CancellationToken cancellationToken) =>
        _sink.IssueAsync(issue, cancellationToken);

    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

    private sealed record PendingFileChange(
        string Path,
        FileChangeKind ChangeKind,
        DateTimeOffset ObservedUtc,
        DateTimeOffset DueUtc);
}
