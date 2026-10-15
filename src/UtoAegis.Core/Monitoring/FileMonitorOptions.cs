namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorOptions
{
    public static readonly TimeSpan DefaultDebounceDelay = TimeSpan.FromMilliseconds(500);
    public static readonly TimeSpan MaximumDebounceDelay = TimeSpan.FromSeconds(60);

    public FileMonitorOptions(
        TimeSpan? debounceDelay = null,
        bool runInitialScan = true)
    {
        DebounceDelay = debounceDelay ?? DefaultDebounceDelay;
        if (DebounceDelay < TimeSpan.Zero || DebounceDelay > MaximumDebounceDelay)
        {
            throw new ArgumentOutOfRangeException(
                nameof(debounceDelay),
                $"Debounce delay must be from zero to {MaximumDebounceDelay.TotalSeconds} seconds.");
        }

        RunInitialScan = runInitialScan;
    }

    public TimeSpan DebounceDelay { get; }

    public bool RunInitialScan { get; }
}
