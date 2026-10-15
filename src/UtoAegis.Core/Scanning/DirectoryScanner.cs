using System.Collections.Concurrent;
using System.Diagnostics;

namespace UtoAegis.Core.Scanning;

public sealed class DirectoryScanner : IDirectoryScanner
{
    private readonly IFileScanner _fileScanner;
    private readonly DirectoryScanOptions _options;

    public DirectoryScanner(
        IFileScanner fileScanner,
        DirectoryScanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(fileScanner);
        _fileScanner = fileScanner;
        _options = options ?? new DirectoryScanOptions();
    }

    public async ValueTask<DirectoryScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(path))
        {
            return Failure(
                DirectoryScanStatus.InvalidPath,
                rootPath: null,
                [],
                stopwatch,
                "A non-empty directory path is required.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return Failure(
                DirectoryScanStatus.InvalidPath,
                rootPath: null,
                [],
                stopwatch,
                "The supplied directory path is not valid on this system.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        FileAttributes rootAttributes;
        try
        {
            rootAttributes = File.GetAttributes(fullPath);
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                DirectoryScanStatus.AccessDenied,
                fullPath,
                [],
                stopwatch,
                "Access to the root directory was denied.");
        }
        catch (Exception exception) when (
            exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return Failure(
                DirectoryScanStatus.DirectoryNotFound,
                fullPath,
                [],
                stopwatch,
                "The root directory does not exist.");
        }
        catch (IOException)
        {
            return Failure(
                DirectoryScanStatus.IoError,
                fullPath,
                [],
                stopwatch,
                "The root directory could not be inspected because of an I/O error.");
        }

        if (!rootAttributes.HasFlag(FileAttributes.Directory))
        {
            return Failure(
                DirectoryScanStatus.NotADirectory,
                fullPath,
                [],
                stopwatch,
                "The supplied path does not refer to a directory.");
        }

        if (rootAttributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return Failure(
                DirectoryScanStatus.ReparsePointNotAllowed,
                fullPath,
                [],
                stopwatch,
                "A reparse point cannot be used as the scan root.");
        }

        var discovery = DiscoverFiles(fullPath, cancellationToken);
        if (discovery.FailureStatus is { } failureStatus)
        {
            return Failure(
                failureStatus,
                fullPath,
                discovery.Issues,
                stopwatch,
                discovery.ErrorMessage!);
        }

        var scanResults = new ConcurrentBag<DirectoryFileScanResult>();
        await Parallel.ForEachAsync(
            discovery.Files,
            new ParallelOptions
            {
                CancellationToken = cancellationToken,
                MaxDegreeOfParallelism = _options.MaximumConcurrency
            },
            async (filePath, token) =>
            {
                var result = await _fileScanner.ScanAsync(filePath, token).ConfigureAwait(false);
                scanResults.Add(new DirectoryFileScanResult(filePath, result));
            }).ConfigureAwait(false);

        stopwatch.Stop();
        var orderedResults = scanResults
            .OrderBy(result => result.Path, StringComparer.Ordinal)
            .ToArray();
        var orderedIssues = discovery.Issues
            .OrderBy(issue => issue.Path, StringComparer.Ordinal)
            .ThenBy(issue => issue.Kind)
            .ToArray();
        return DirectoryScanResult.Finished(
            fullPath,
            orderedResults,
            orderedIssues,
            stopwatch.Elapsed);
    }

    private DiscoveryResult DiscoverFiles(
        string rootPath,
        CancellationToken cancellationToken)
    {
        var files = new List<string>();
        var issues = new List<DirectoryScanIssue>();
        var directories = new Stack<(string Path, int Depth)>();
        directories.Push((rootPath, 0));
        var directoryCount = 1;

        while (directories.TryPop(out var current))
        {
            cancellationToken.ThrowIfCancellationRequested();

            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(current.Path);
                Array.Sort(entries, StringComparer.Ordinal);
            }
            catch (UnauthorizedAccessException)
            {
                issues.Add(new DirectoryScanIssue(
                    current.Path,
                    DirectoryScanIssueKind.AccessDenied,
                    "Access to the directory was denied."));
                continue;
            }
            catch (Exception exception) when (
                exception is FileNotFoundException or DirectoryNotFoundException)
            {
                issues.Add(new DirectoryScanIssue(
                    current.Path,
                    DirectoryScanIssueKind.EntryDisappeared,
                    "The directory disappeared during traversal."));
                continue;
            }
            catch (IOException)
            {
                issues.Add(new DirectoryScanIssue(
                    current.Path,
                    DirectoryScanIssueKind.IoError,
                    "The directory could not be enumerated because of an I/O error."));
                continue;
            }

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileAttributes attributes;
                try
                {
                    attributes = File.GetAttributes(entry);
                }
                catch (UnauthorizedAccessException)
                {
                    issues.Add(new DirectoryScanIssue(
                        entry,
                        DirectoryScanIssueKind.AccessDenied,
                        "Access to the entry was denied."));
                    continue;
                }
                catch (Exception exception) when (
                    exception is FileNotFoundException or DirectoryNotFoundException)
                {
                    issues.Add(new DirectoryScanIssue(
                        entry,
                        DirectoryScanIssueKind.EntryDisappeared,
                        "The entry disappeared during traversal."));
                    continue;
                }
                catch (IOException)
                {
                    issues.Add(new DirectoryScanIssue(
                        entry,
                        DirectoryScanIssueKind.IoError,
                        "The entry could not be inspected because of an I/O error."));
                    continue;
                }

                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    issues.Add(new DirectoryScanIssue(
                        entry,
                        DirectoryScanIssueKind.ReparsePointSkipped,
                        "The reparse point was not followed."));
                    continue;
                }

                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    if (!_options.Recurse)
                    {
                        continue;
                    }

                    if (current.Depth >= _options.MaximumDepth)
                    {
                        issues.Add(new DirectoryScanIssue(
                            entry,
                            DirectoryScanIssueKind.DepthLimitReached,
                            $"The recursion depth limit of {_options.MaximumDepth} was reached."));
                        continue;
                    }

                    directoryCount++;
                    if (directoryCount > _options.MaximumDirectoryCount)
                    {
                        return DiscoveryResult.Failed(
                            files,
                            issues,
                            DirectoryScanStatus.DirectoryLimitExceeded,
                            $"The directory count exceeded the {_options.MaximumDirectoryCount}-directory limit.");
                    }

                    directories.Push((entry, current.Depth + 1));
                    continue;
                }

                files.Add(entry);
                if (files.Count > _options.MaximumFileCount)
                {
                    return DiscoveryResult.Failed(
                        files,
                        issues,
                        DirectoryScanStatus.FileLimitExceeded,
                        $"The file count exceeded the {_options.MaximumFileCount}-file limit.");
                }
            }
        }

        files.Sort(StringComparer.Ordinal);
        return DiscoveryResult.Succeeded(files, issues);
    }

    private static DirectoryScanResult Failure(
        DirectoryScanStatus status,
        string? rootPath,
        IReadOnlyList<DirectoryScanIssue> issues,
        Stopwatch stopwatch,
        string message)
    {
        stopwatch.Stop();
        return DirectoryScanResult.Failure(status, rootPath, issues, stopwatch.Elapsed, message);
    }

    private sealed record DiscoveryResult(
        IReadOnlyList<string> Files,
        IReadOnlyList<DirectoryScanIssue> Issues,
        DirectoryScanStatus? FailureStatus,
        string? ErrorMessage)
    {
        public static DiscoveryResult Succeeded(
            IReadOnlyList<string> files,
            IReadOnlyList<DirectoryScanIssue> issues) =>
            new(files, issues, FailureStatus: null, ErrorMessage: null);

        public static DiscoveryResult Failed(
            IReadOnlyList<string> files,
            IReadOnlyList<DirectoryScanIssue> issues,
            DirectoryScanStatus failureStatus,
            string errorMessage) =>
            new(files, issues, failureStatus, errorMessage);
    }
}
