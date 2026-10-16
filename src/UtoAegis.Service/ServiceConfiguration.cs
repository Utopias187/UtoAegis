using System.Globalization;
using Microsoft.Extensions.Configuration;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;
using UtoAegis.Infrastructure.Monitoring;

namespace UtoAegis.Service;

public sealed class ServiceConfiguration
{
    public static readonly TimeSpan MinimumHealthInterval = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan MaximumHealthInterval = TimeSpan.FromHours(24);

    private ServiceConfiguration(
        string monitorRoot,
        bool recursive,
        bool runInitialScan,
        string? databasePath,
        string? signaturePath,
        string? historyPath,
        string? vaultPath,
        int maximumConcurrency,
        int queueCapacity,
        int watcherBufferSize,
        TimeSpan debounceDelay,
        TimeSpan healthInterval,
        ResponsePolicy responsePolicy)
    {
        MonitorRoot = monitorRoot;
        Recursive = recursive;
        RunInitialScan = runInitialScan;
        DatabasePath = databasePath;
        SignaturePath = signaturePath;
        HistoryPath = historyPath;
        VaultPath = vaultPath;
        MaximumConcurrency = maximumConcurrency;
        QueueCapacity = queueCapacity;
        WatcherBufferSize = watcherBufferSize;
        DebounceDelay = debounceDelay;
        HealthInterval = healthInterval;
        ResponsePolicy = responsePolicy;
    }

    public string MonitorRoot { get; }

    public bool Recursive { get; }

    public bool RunInitialScan { get; }

    public string? DatabasePath { get; }

    public string? SignaturePath { get; }

    public string? HistoryPath { get; }

    public string? VaultPath { get; }

    public int MaximumConcurrency { get; }

    public int QueueCapacity { get; }

    public int WatcherBufferSize { get; }

    public TimeSpan DebounceDelay { get; }

    public TimeSpan HealthInterval { get; }

    public ResponsePolicy ResponsePolicy { get; }

    public IReadOnlyCollection<string> OperationalExclusions
    {
        get
        {
            var paths = new List<string>();
            if (DatabasePath is not null)
            {
                paths.Add(DatabasePath);
                paths.Add(DatabasePath + "-shm");
                paths.Add(DatabasePath + "-wal");
            }

            if (HistoryPath is not null)
            {
                paths.Add(HistoryPath);
                paths.Add(HistoryPath + "-shm");
                paths.Add(HistoryPath + "-wal");
            }

            if (SignaturePath is not null)
            {
                paths.Add(SignaturePath);
            }

            return paths;
        }
    }

    public static ServiceConfiguration Load(
        IConfiguration configuration,
        string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        var section = configuration.GetSection("UtoAegis");

        try
        {
            var monitorRoot = RequiredPath(section, "MonitorRoot", baseDirectory);
            ValidateMonitorRoot(monitorRoot);

            var databasePath = OptionalPath(section, "DatabasePath", baseDirectory);
            var signaturePath = OptionalPath(section, "SignaturePath", baseDirectory);
            var historyPath = OptionalPath(section, "HistoryPath", baseDirectory);
            var vaultPath = OptionalPath(section, "VaultPath", baseDirectory);
            if (databasePath is null && signaturePath is null)
            {
                throw new ServiceConfigurationException(
                    "UtoAegis requires DatabasePath, SignaturePath, or both as a detection source.");
            }

            if (signaturePath is not null && !File.Exists(signaturePath))
            {
                throw new ServiceConfigurationException(
                    "The configured signature rule file does not exist.");
            }

            ValidateDistinctOperationalPaths(databasePath, signaturePath, historyPath, vaultPath);

            var responseSection = section.GetSection("Response");
            var mode = ParseEnum(
                responseSection,
                "Mode",
                ResponseMode.ObserveOnly);
            if (mode == ResponseMode.Quarantine && vaultPath is null)
            {
                throw new ServiceConfigurationException(
                    "Quarantine response mode requires VaultPath.");
            }

            var writablePaths = new[] { databasePath, historyPath, vaultPath }
                .Where(path => path is not null)
                .Select(path => path!)
                .ToArray();
            if (writablePaths.Any(path => IsWithin(monitorRoot, path)))
            {
                throw new ServiceConfigurationException(
                    "DatabasePath, HistoryPath, and VaultPath must be outside MonitorRoot " +
                    "to preserve least privilege and prevent monitoring loops.");
            }

            var writableDirectories = writablePaths
                .Select(path => path == vaultPath ? path : Path.GetDirectoryName(path)!)
                .Distinct(OperatingSystem.IsWindows()
                    ? StringComparer.OrdinalIgnoreCase
                    : StringComparer.Ordinal)
                .ToArray();
            var installationDirectory = Path.GetFullPath(baseDirectory);
            if (writableDirectories.Any(directory =>
                    PathEquals(directory, Path.GetPathRoot(directory)!) ||
                    IsWithin(directory, installationDirectory)))
            {
                throw new ServiceConfigurationException(
                    "Writable state directories must not be filesystem roots or contain " +
                    "the service installation directory.");
            }

            if (signaturePath is not null &&
                writableDirectories.Any(directory => IsWithin(directory, signaturePath)))
            {
                throw new ServiceConfigurationException(
                    "SignaturePath must be outside writable state directories.");
            }

            if (IsWithin(monitorRoot, installationDirectory))
            {
                throw new ServiceConfigurationException(
                    "The service installation directory must be outside MonitorRoot.");
            }

            var responsePolicy = new ResponsePolicy(
                mode,
                ReadValues(responseSection.GetSection("AllowlistedPathPrefixes")),
                ReadValues(responseSection.GetSection("AllowlistedSha256")),
                ReadInt(responseSection, "MaxActionsPerWindow", 3),
                TimeSpan.FromSeconds(ReadInt(responseSection, "RateLimitWindowSeconds", 300)));

            var healthInterval = TimeSpan.FromSeconds(
                ReadInt(section, "HealthIntervalSeconds", 60));
            if (healthInterval < MinimumHealthInterval || healthInterval > MaximumHealthInterval)
            {
                throw new ServiceConfigurationException(
                    "HealthIntervalSeconds must be from 10 through 86400.");
            }

            var recursive = ReadBoolean(section, "Recursive", defaultValue: true);
            var runInitialScan = ReadBoolean(section, "RunInitialScan", defaultValue: true);
            var maximumConcurrency = ReadInt(
                section,
                "MaximumConcurrency",
                DirectoryScanOptions.DefaultMaximumConcurrency);
            var queueCapacity = ReadInt(
                section,
                "QueueCapacity",
                FileSystemWatcherEventSource.DefaultQueueCapacity);
            var watcherBufferSize = ReadInt(
                section,
                "WatcherBufferSize",
                FileSystemWatcherEventSource.DefaultInternalBufferSize);
            var debounceDelay = TimeSpan.FromMilliseconds(
                ReadInt(
                    section,
                    "DebounceMilliseconds",
                    (int)FileMonitorOptions.DefaultDebounceDelay.TotalMilliseconds));
            _ = new DirectoryScanOptions(recursive, maximumConcurrency);
            _ = new FileMonitorOptions(debounceDelay, runInitialScan);
            if (queueCapacity is < 1 or > FileSystemWatcherEventSource.MaximumQueueCapacity)
            {
                throw new ServiceConfigurationException(
                    $"QueueCapacity must be from 1 through {FileSystemWatcherEventSource.MaximumQueueCapacity}.");
            }

            if (watcherBufferSize is < 4_096 or > FileSystemWatcherEventSource.MaximumInternalBufferSize)
            {
                throw new ServiceConfigurationException(
                    $"WatcherBufferSize must be from 4096 through {FileSystemWatcherEventSource.MaximumInternalBufferSize}.");
            }

            return new ServiceConfiguration(
                monitorRoot,
                recursive,
                runInitialScan,
                databasePath,
                signaturePath,
                historyPath,
                vaultPath,
                maximumConcurrency,
                queueCapacity,
                watcherBufferSize,
                debounceDelay,
                healthInterval,
                responsePolicy);
        }
        catch (ServiceConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException or
                OverflowException or UnauthorizedAccessException or IOException)
        {
            throw new ServiceConfigurationException(
                "The UtoAegis service configuration is invalid.",
                exception);
        }
    }

    private static string RequiredPath(
        IConfiguration section,
        string key,
        string baseDirectory) =>
        OptionalPath(section, key, baseDirectory) ??
        throw new ServiceConfigurationException($"UtoAegis:{key} is required.");

    private static string? OptionalPath(
        IConfiguration section,
        string key,
        string baseDirectory)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(value.Trim());
        return Path.GetFullPath(expanded, Path.GetFullPath(baseDirectory));
    }

    private static int ReadInt(IConfiguration section, string key, int defaultValue)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new ServiceConfigurationException(
                $"UtoAegis configuration value {key} must be an integer.");
        }

        return parsed;
    }

    private static bool ReadBoolean(
        IConfiguration section,
        string key,
        bool defaultValue)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (!bool.TryParse(value, out var parsed))
        {
            throw new ServiceConfigurationException(
                $"UtoAegis configuration value {key} must be true or false.");
        }

        return parsed;
    }

    private static TEnum ParseEnum<TEnum>(
        IConfiguration section,
        string key,
        TEnum defaultValue)
        where TEnum : struct, Enum
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (!Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsed) ||
            !Enum.IsDefined(parsed))
        {
            throw new ServiceConfigurationException(
                $"UtoAegis configuration value {key} is not supported.");
        }

        return parsed;
    }

    private static string[] ReadValues(IConfiguration section) =>
        section.GetChildren()
            .Select(child => child.Value?.Trim())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .ToArray();

    private static void ValidateMonitorRoot(string path)
    {
        if (!Directory.Exists(path))
        {
            throw new ServiceConfigurationException(
                "The configured monitor root directory does not exist.");
        }

        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new ServiceConfigurationException(
                "A reparse point cannot be used as the monitor root.");
        }
    }

    private static void ValidateDistinctOperationalPaths(params string?[] paths)
    {
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        var values = paths.Where(path => path is not null).Select(path => path!).ToArray();
        if (values.Distinct(comparer).Count() != values.Length)
        {
            throw new ServiceConfigurationException(
                "Database, signature, history, and vault paths must be distinct.");
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        return relative == "." ||
            (!Path.IsPathRooted(relative) &&
             relative != ".." &&
             !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
             !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal));
    }

    private static bool PathEquals(string first, string second) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(first),
            Path.TrimEndingDirectorySeparator(second),
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);
}
