namespace UtoAegis.Core.Monitoring;

public interface IFileMonitorEventSource : IAsyncDisposable
{
    IAsyncEnumerable<FileMonitorEvent> ReadAllAsync(
        CancellationToken cancellationToken = default);
}
