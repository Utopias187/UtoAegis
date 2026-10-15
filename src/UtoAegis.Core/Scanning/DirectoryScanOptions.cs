namespace UtoAegis.Core.Scanning;

public sealed record DirectoryScanOptions
{
    public const int DefaultMaximumConcurrency = 4;
    public const int DefaultMaximumFileCount = 100_000;
    public const int DefaultMaximumDirectoryCount = 50_000;
    public const int DefaultMaximumDepth = 64;
    public const int MaximumAllowedConcurrency = 32;
    public const int MaximumAllowedFileCount = 1_000_000;
    public const int MaximumAllowedDirectoryCount = 250_000;
    public const int MaximumAllowedDepth = 256;

    public DirectoryScanOptions(
        bool recurse = false,
        int maximumConcurrency = DefaultMaximumConcurrency,
        int maximumFileCount = DefaultMaximumFileCount,
        int maximumDirectoryCount = DefaultMaximumDirectoryCount,
        int maximumDepth = DefaultMaximumDepth)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumConcurrency, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maximumConcurrency,
            MaximumAllowedConcurrency);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumFileCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maximumFileCount,
            MaximumAllowedFileCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumDirectoryCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maximumDirectoryCount,
            MaximumAllowedDirectoryCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumDepth, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumDepth, MaximumAllowedDepth);

        Recurse = recurse;
        MaximumConcurrency = maximumConcurrency;
        MaximumFileCount = maximumFileCount;
        MaximumDirectoryCount = maximumDirectoryCount;
        MaximumDepth = maximumDepth;
    }

    public bool Recurse { get; }

    public int MaximumConcurrency { get; }

    public int MaximumFileCount { get; }

    public int MaximumDirectoryCount { get; }

    public int MaximumDepth { get; }
}
