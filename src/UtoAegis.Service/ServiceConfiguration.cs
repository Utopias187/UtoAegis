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
        string? contentStorePath,
        IReadOnlyDictionary<string, string> trustedSigningKeyPaths,
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
        ContentStorePath = contentStorePath;
        TrustedSigningKeyPaths = trustedSigningKeyPaths;
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

    public string? ContentStorePath { get; }

    public IReadOnlyDictionary<string, string> TrustedSigningKeyPaths { get; }

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

            if (ContentStorePath is not null)
            {
                paths.Add(ContentStorePath);
            }

            paths.AddRange(TrustedSigningKeyPaths.Values);

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
            var contentStorePath = OptionalPath(section, "ContentStorePath", baseDirectory);
            var trustedSigningKeyPaths = ReadTrustedSigningKeys(
                section.GetSection("TrustedSigningKeys"),
                baseDirectory);
            var historyPath = OptionalPath(section, "HistoryPath", baseDirectory);
            var vaultPath = OptionalPath(section, "VaultPath", baseDirectory);
            if (contentStorePath is null && databasePath is null && signaturePath is null)
            {
                throw new ServiceConfigurationException(
                    "UtoAegis requires a detection source: ContentStorePath, DatabasePath, SignaturePath, or both direct paths.");
            }

            if (contentStorePath is not null &&
                (databasePath is not null || signaturePath is not null))
            {
                throw new ServiceConfigurationException(
                    "ContentStorePath cannot be combined with DatabasePath or SignaturePath.");
            }

            if (contentStorePath is not null && trustedSigningKeyPaths.Count == 0)
            {
                throw new ServiceConfigurationException(
                    "ContentStorePath requires at least one TrustedSigningKeys entry.");
            }

            if (contentStorePath is not null &&
                (!Directory.Exists(contentStorePath) ||
                 File.GetAttributes(contentStorePath).HasFlag(FileAttributes.ReparsePoint)))
            {
                throw new ServiceConfigurationException(
                    "ContentStorePath must reference an existing regular directory.");
            }

            if (contentStorePath is null && trustedSigningKeyPaths.Count != 0)
            {
                throw new ServiceConfigurationException(
                    "TrustedSigningKeys requires ContentStorePath.");
            }

            if (signaturePath is not null && !File.Exists(signaturePath))
            {
                throw new ServiceConfigurationException(
                    "The configured signature rule file does not exist.");
            }

            ValidateDistinctOperationalPaths(
                databasePath,
                signaturePath,
                contentStorePath,
                historyPath,
                vaultPath);

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

            if (contentStorePath is not null && IsWithin(monitorRoot, contentStorePath))
            {
                throw new ServiceConfigurationException(
                    "ContentStorePath must be outside MonitorRoot to prevent monitoring loops.");
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

            if (contentStorePath is not null &&
                (PathEquals(contentStorePath, Path.GetPathRoot(contentStorePath)!) ||
                 IsWithin(contentStorePath, installationDirectory) ||
                 IsWithin(installationDirectory, contentStorePath)))
            {
                throw new ServiceConfigurationException(
                    "ContentStorePath must not be a filesystem root, contain the service installation, or be inside it.");
            }

            if (signaturePath is not null &&
                writableDirectories.Any(directory => IsWithin(directory, signaturePath)))
            {
                throw new ServiceConfigurationException(
                    "SignaturePath must be outside writable state directories.");
            }

            if (contentStorePath is not null && trustedSigningKeyPaths.Values.Any(path =>
                    IsWithin(contentStorePath, path) ||
                    writableDirectories.Any(directory => IsWithin(directory, path))))
            {
                throw new ServiceConfigurationException(
                    "Trusted signing keys must be outside the content store and writable state directories.");
            }

            if (IsWithin(monitorRoot, installationDirectory))
            {
                throw new ServiceConfigurationException(
                    "The service installation directory must be outside MonitorRoot.");
            }

            var responsePolicy = new ResponsePolicy(
                mode,
                ReadValues(responseSection.GetSection("AllowlistedPathPrefixes"))
                    .Select(path => ResolvePath(path, baseDirectory))
                    .ToArray(),
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
                contentStorePath,
                trustedSigningKeyPaths,
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

        return ResolvePath(value, baseDirectory);
    }

    private static string ResolvePath(string value, string baseDirectory)
    {
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

    private static Dictionary<string, string> ReadTrustedSigningKeys(
        IConfiguration section,
        string baseDirectory)
    {
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var child in section.GetChildren())
        {
            var keyId = child["KeyId"]?.Trim();
            var publicKeyPath = child["PublicKeyPath"];
            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(publicKeyPath))
            {
                throw new ServiceConfigurationException(
                    "Every TrustedSigningKeys entry requires KeyId and PublicKeyPath.");
            }

            var resolvedPath = ResolvePath(publicKeyPath, baseDirectory);
            if (!File.Exists(resolvedPath) ||
                File.GetAttributes(resolvedPath).HasFlag(FileAttributes.ReparsePoint))
            {
                throw new ServiceConfigurationException(
                    $"Trusted signing key '{keyId}' must reference an existing regular file.");
            }

            if (!keys.TryAdd(keyId, resolvedPath))
            {
                throw new ServiceConfigurationException(
                    $"Trusted signing key id '{keyId}' is duplicated.");
            }

            if (keys.Count > 32)
            {
                throw new ServiceConfigurationException(
                    "At most 32 trusted signing keys may be configured.");
            }
        }

        return keys;
    }

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
                "Database, signature, content store, history, and vault paths must be distinct.");
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
