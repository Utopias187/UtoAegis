using UtoAegis.Core.Reputation;

namespace UtoAegis.Core.Response;

public sealed class ResponsePolicy
{
    public const int MaximumAllowlistedPathCount = 1_024;
    public const int MaximumAllowlistedHashCount = 10_000;
    public const int MaximumActionsPerWindow = 100;

    private static readonly StringComparer PathComparer = OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    public ResponsePolicy(
        ResponseMode mode = ResponseMode.ObserveOnly,
        IReadOnlyCollection<string>? allowlistedPathPrefixes = null,
        IReadOnlyCollection<string>? allowlistedSha256 = null,
        int maxActionsPerWindow = 3,
        TimeSpan? rateLimitWindow = null)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(maxActionsPerWindow, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maxActionsPerWindow,
            MaximumActionsPerWindow);

        var window = rateLimitWindow ?? TimeSpan.FromMinutes(5);
        if (window < TimeSpan.FromSeconds(1) || window > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(
                nameof(rateLimitWindow),
                "The rate-limit window must be between one second and 24 hours.");
        }

        Mode = mode;
        MaxActionsPerWindow = maxActionsPerWindow;
        RateLimitWindow = window;
        AllowlistedPathPrefixes = NormalizePaths(allowlistedPathPrefixes ?? []);
        AllowlistedSha256 = NormalizeHashes(allowlistedSha256 ?? []);
    }

    public ResponseMode Mode { get; }

    public IReadOnlyList<string> AllowlistedPathPrefixes { get; }

    public IReadOnlySet<string> AllowlistedSha256 { get; }

    public int MaxActionsPerWindow { get; }

    public TimeSpan RateLimitWindow { get; }

    public bool IsPathAllowlisted(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var candidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        return AllowlistedPathPrefixes.Any(prefix =>
            PathComparer.Equals(candidate, prefix) ||
            candidate.StartsWith(WithTrailingSeparator(prefix), PathComparison));
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static string WithTrailingSeparator(string path) =>
        Path.EndsInDirectorySeparator(path)
            ? path
            : path + Path.DirectorySeparatorChar;

    private static string[] NormalizePaths(IReadOnlyCollection<string> paths)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            paths.Count,
            MaximumAllowlistedPathCount);
        return paths
            .Select(path =>
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(path);
                return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            })
            .Distinct(PathComparer)
            .Order(PathComparer)
            .ToArray();
    }

    private static HashSet<string> NormalizeHashes(IReadOnlyCollection<string> hashes)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            hashes.Count,
            MaximumAllowlistedHashCount);
        var normalized = new HashSet<string>(StringComparer.Ordinal);
        foreach (var hash in hashes)
        {
            if (!MalwareHashIndicator.TryNormalizeSha256(hash, out var value))
            {
                throw new ArgumentException(
                    "Every allowlisted SHA-256 must contain exactly 64 hexadecimal characters.",
                    nameof(hashes));
            }

            normalized.Add(value!);
        }

        return normalized;
    }
}
