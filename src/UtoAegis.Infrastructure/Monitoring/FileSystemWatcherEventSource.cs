using System.Runtime.CompilerServices;
using UtoAegis.Core.Monitoring;

namespace UtoAegis.Infrastructure.Monitoring;

public sealed class FileSystemWatcherEventSource : IFileMonitorEventSource
{
    public const int DefaultQueueCapacity = 4_096;
    public const int MaximumQueueCapacity = 65_536;
    public const int DefaultInternalBufferSize = 16 * 1_024;
    public const int MaximumInternalBufferSize = 64 * 1_024;

    private readonly FileSystemWatcher _watcher;
    private readonly BoundedFileMonitorEventQueue _queue;
    private readonly TimeProvider _timeProvider;
    private readonly HashSet<string> _excludedPaths;
    private int _disposed;
    private int _readerStarted;

    public FileSystemWatcherEventSource(
        string rootPath,
        bool includeSubdirectories,
        int queueCapacity = DefaultQueueCapacity,
        int internalBufferSize = DefaultInternalBufferSize,
        IReadOnlyCollection<string>? excludedPaths = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        if (queueCapacity is < 1 or > MaximumQueueCapacity)
        {
            throw new ArgumentOutOfRangeException(
                nameof(queueCapacity),
                $"Queue capacity must be from 1 to {MaximumQueueCapacity}.");
        }

        if (internalBufferSize is < 4_096 or > MaximumInternalBufferSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(internalBufferSize),
                $"Watcher buffer size must be from 4096 to {MaximumInternalBufferSize} bytes.");
        }

        var normalizedRoot = Path.GetFullPath(rootPath);
        if (!Directory.Exists(normalizedRoot))
        {
            throw new DirectoryNotFoundException("The monitor root directory does not exist.");
        }

        var attributes = File.GetAttributes(normalizedRoot);
        if ((attributes & FileAttributes.Directory) == 0)
        {
            throw new ArgumentException("The monitor root must be a directory.", nameof(rootPath));
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new ArgumentException("A reparse point cannot be used as the monitor root.", nameof(rootPath));
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
        _excludedPaths = new HashSet<string>(
            excludedPaths?.Select(Path.GetFullPath) ?? [],
            OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal);
        _queue = new BoundedFileMonitorEventQueue(queueCapacity, _timeProvider);
        _watcher = new FileSystemWatcher(normalizedRoot)
        {
            IncludeSubdirectories = includeSubdirectories,
            InternalBufferSize = internalBufferSize,
            NotifyFilter = NotifyFilters.FileName |
                NotifyFilters.LastWrite |
                NotifyFilters.Size |
                NotifyFilters.CreationTime
        };
        _watcher.Created += OnCreated;
        _watcher.Changed += OnChanged;
        _watcher.Renamed += OnRenamed;
        _watcher.Error += OnError;

        try
        {
            _watcher.EnableRaisingEvents = true;
        }
        catch
        {
            UnsubscribeAndDisposeWatcher();
            _queue.Complete();
            throw;
        }
    }

    public IAsyncEnumerable<FileMonitorEvent> ReadAllAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _readerStarted, 1) != 0)
        {
            throw new InvalidOperationException("The file-event source supports one reader.");
        }

        return ReadAllCoreAsync(cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            UnsubscribeAndDisposeWatcher();
            _queue.Complete();
        }

        return ValueTask.CompletedTask;
    }

    private async IAsyncEnumerable<FileMonitorEvent> ReadAllCoreAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var monitorEvent in _queue
                           .ReadAllAsync(cancellationToken)
                           .ConfigureAwait(false))
        {
            yield return monitorEvent;
        }
    }

    private void OnCreated(object sender, FileSystemEventArgs eventArgs) =>
        PublishFileChange(eventArgs.FullPath, FileChangeKind.Created);

    private void OnChanged(object sender, FileSystemEventArgs eventArgs) =>
        PublishFileChange(eventArgs.FullPath, FileChangeKind.Changed);

    private void OnRenamed(object sender, RenamedEventArgs eventArgs) =>
        PublishFileChange(eventArgs.FullPath, FileChangeKind.Renamed);

    private void OnError(object sender, ErrorEventArgs eventArgs)
    {
        var exception = eventArgs.GetException();
        if (exception is InternalBufferOverflowException)
        {
            _queue.TryPublish(FileMonitorEvent.Overflow(
                _timeProvider.GetUtcNow(),
                "The operating-system watcher buffer overflowed; one or more events were lost."));
            return;
        }

        _queue.TryPublish(FileMonitorEvent.SourceError(
            _timeProvider.GetUtcNow(),
            exception?.Message ?? "The operating-system watcher reported an unknown error."));
    }

    private void PublishFileChange(string path, FileChangeKind changeKind)
    {
        string normalizedPath;
        try
        {
            normalizedPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            _queue.TryPublish(FileMonitorEvent.SourceError(
                _timeProvider.GetUtcNow(),
                $"A watcher event contained an invalid path: {exception.Message}"));
            return;
        }

        if (_excludedPaths.Contains(normalizedPath))
        {
            return;
        }

        _queue.TryPublish(FileMonitorEvent.FileChanged(
            normalizedPath,
            changeKind,
            _timeProvider.GetUtcNow()));
    }

    private void UnsubscribeAndDisposeWatcher()
    {
        _watcher.EnableRaisingEvents = false;
        _watcher.Created -= OnCreated;
        _watcher.Changed -= OnChanged;
        _watcher.Renamed -= OnRenamed;
        _watcher.Error -= OnError;
        _watcher.Dispose();
    }
}
