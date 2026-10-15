using System.Runtime.CompilerServices;
using System.Threading.Channels;
using UtoAegis.Core.Monitoring;

namespace UtoAegis.Infrastructure.Monitoring;

internal sealed class BoundedFileMonitorEventQueue
{
    private readonly Channel<FileMonitorEvent> _channel;
    private readonly TimeProvider _timeProvider;
    private int _overflowPending;

    public BoundedFileMonitorEventQueue(int capacity, TimeProvider timeProvider)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _channel = Channel.CreateBounded<FileMonitorEvent>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });
    }

    public bool TryPublish(FileMonitorEvent monitorEvent)
    {
        ArgumentNullException.ThrowIfNull(monitorEvent);
        if (_channel.Writer.TryWrite(monitorEvent))
        {
            return true;
        }

        Interlocked.Exchange(ref _overflowPending, 1);
        return false;
    }

    public void Complete() => _channel.Writer.TryComplete();

    public async IAsyncEnumerable<FileMonitorEvent> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        while (await _channel.Reader
                   .WaitToReadAsync(cancellationToken)
                   .ConfigureAwait(false))
        {
            while (_channel.Reader.TryRead(out var monitorEvent))
            {
                yield return monitorEvent;
            }

            if (Interlocked.Exchange(ref _overflowPending, 0) != 0)
            {
                yield return FileMonitorEvent.Overflow(
                    _timeProvider.GetUtcNow(),
                    "The bounded file-event queue overflowed; one or more events were lost.");
            }
        }

        if (Interlocked.Exchange(ref _overflowPending, 0) != 0)
        {
            yield return FileMonitorEvent.Overflow(
                _timeProvider.GetUtcNow(),
                "The bounded file-event queue overflowed; one or more events were lost.");
        }
    }
}
