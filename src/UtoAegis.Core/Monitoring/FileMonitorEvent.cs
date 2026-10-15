namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorEvent
{
    private FileMonitorEvent(
        FileMonitorEventKind kind,
        string? path,
        FileChangeKind? changeKind,
        DateTimeOffset observedUtc,
        string? message)
    {
        Kind = kind;
        Path = path;
        ChangeKind = changeKind;
        ObservedUtc = observedUtc;
        Message = message;
    }

    public FileMonitorEventKind Kind { get; }

    public string? Path { get; }

    public FileChangeKind? ChangeKind { get; }

    public DateTimeOffset ObservedUtc { get; }

    public string? Message { get; }

    public static FileMonitorEvent FileChanged(
        string path,
        FileChangeKind changeKind,
        DateTimeOffset observedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new FileMonitorEvent(
            FileMonitorEventKind.FileChanged,
            path,
            changeKind,
            observedUtc,
            message: null);
    }

    public static FileMonitorEvent Overflow(DateTimeOffset observedUtc, string message) =>
        new(
            FileMonitorEventKind.Overflow,
            path: null,
            changeKind: null,
            observedUtc,
            message);

    public static FileMonitorEvent SourceError(DateTimeOffset observedUtc, string message) =>
        new(
            FileMonitorEventKind.SourceError,
            path: null,
            changeKind: null,
            observedUtc,
            message);
}
