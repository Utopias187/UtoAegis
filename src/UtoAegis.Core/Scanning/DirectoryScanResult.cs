namespace UtoAegis.Core.Scanning;

public sealed record DirectoryScanResult
{
    private DirectoryScanResult(
        DirectoryScanStatus status,
        string? rootPath,
        IReadOnlyList<DirectoryFileScanResult> files,
        IReadOnlyList<DirectoryScanIssue> issues,
        TimeSpan elapsed,
        string? errorMessage)
    {
        Status = status;
        RootPath = rootPath;
        Files = files.ToArray();
        Issues = issues.ToArray();
        Elapsed = elapsed;
        ErrorMessage = errorMessage;
    }

    public DirectoryScanStatus Status { get; }

    public string? RootPath { get; }

    public IReadOnlyList<DirectoryFileScanResult> Files { get; }

    public IReadOnlyList<DirectoryScanIssue> Issues { get; }

    public TimeSpan Elapsed { get; }

    public string? ErrorMessage { get; }

    public int DetectedFileCount => Files.Count(file => file.Result.IsDetected);

    public int FailedFileCount => Files.Count(file => !file.Result.IsCompleted);

    public bool HasDetections => DetectedFileCount > 0;

    public bool IsCompleted => Status is DirectoryScanStatus.Completed or DirectoryScanStatus.Partial;

    public static DirectoryScanResult Finished(
        string rootPath,
        IReadOnlyList<DirectoryFileScanResult> files,
        IReadOnlyList<DirectoryScanIssue> issues,
        TimeSpan elapsed)
    {
        var status = issues.Count == 0 && files.All(file => file.Result.IsCompleted)
            ? DirectoryScanStatus.Completed
            : DirectoryScanStatus.Partial;
        return new DirectoryScanResult(status, rootPath, files, issues, elapsed, null);
    }

    public static DirectoryScanResult Failure(
        DirectoryScanStatus status,
        string? rootPath,
        IReadOnlyList<DirectoryScanIssue> issues,
        TimeSpan elapsed,
        string errorMessage) =>
        new(status, rootPath, [], issues, elapsed, errorMessage);
}
