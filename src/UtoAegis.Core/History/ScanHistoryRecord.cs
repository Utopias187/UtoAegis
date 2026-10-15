using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.History;

public sealed record ScanHistoryRecord
{
    private ScanHistoryRecord(
        Guid id,
        ScanHistoryTargetKind targetKind,
        string targetPath,
        bool recursive,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        ScanHistoryOutcome outcome,
        IReadOnlyList<ScanHistoryFile> files,
        IReadOnlyList<ScanHistoryIssue> issues,
        string? errorMessage)
    {
        Id = id;
        TargetKind = targetKind;
        TargetPath = targetPath;
        Recursive = recursive;
        StartedUtc = startedUtc;
        CompletedUtc = completedUtc;
        Outcome = outcome;
        Files = files.ToArray();
        Issues = issues.ToArray();
        ErrorMessage = errorMessage;
    }

    public Guid Id { get; }

    public ScanHistoryTargetKind TargetKind { get; }

    public string TargetPath { get; }

    public bool Recursive { get; }

    public DateTimeOffset StartedUtc { get; }

    public DateTimeOffset CompletedUtc { get; }

    public ScanHistoryOutcome Outcome { get; }

    public IReadOnlyList<ScanHistoryFile> Files { get; }

    public IReadOnlyList<ScanHistoryIssue> Issues { get; }

    public string? ErrorMessage { get; }

    public int DetectedFileCount => Files.Count(file => file.Detected);

    public int FailedFileCount => Files.Count(file => !file.Completed);

    public static ScanHistoryRecord FromFileScan(
        Guid id,
        string targetPath,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        FileScanResult result)
    {
        Validate(id, targetPath, startedUtc, completedUtc);
        ArgumentNullException.ThrowIfNull(result);

        return new ScanHistoryRecord(
            id,
            ScanHistoryTargetKind.File,
            targetPath,
            recursive: false,
            startedUtc,
            completedUtc,
            result.IsCompleted ? ScanHistoryOutcome.Completed : ScanHistoryOutcome.Failed,
            [ScanHistoryFile.FromResult(result.Path ?? targetPath, result)],
            [],
            FirstError(result));
    }

    public static ScanHistoryRecord FromDirectoryScan(
        Guid id,
        string targetPath,
        bool recursive,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        DirectoryScanResult result)
    {
        Validate(id, targetPath, startedUtc, completedUtc);
        ArgumentNullException.ThrowIfNull(result);

        var outcome = result.Status switch
        {
            DirectoryScanStatus.Completed => ScanHistoryOutcome.Completed,
            DirectoryScanStatus.Partial => ScanHistoryOutcome.Partial,
            _ => ScanHistoryOutcome.Failed
        };

        return new ScanHistoryRecord(
            id,
            ScanHistoryTargetKind.Directory,
            targetPath,
            recursive,
            startedUtc,
            completedUtc,
            outcome,
            result.Files
                .Select(file => ScanHistoryFile.FromResult(file.Path, file.Result))
                .ToArray(),
            result.Issues
                .Select(issue => new ScanHistoryIssue(issue.Path, issue.Kind, issue.Message))
                .ToArray(),
            result.ErrorMessage);
    }

    public static ScanHistoryRecord Restore(
        Guid id,
        ScanHistoryTargetKind targetKind,
        string targetPath,
        bool recursive,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        ScanHistoryOutcome outcome,
        IReadOnlyList<ScanHistoryFile> files,
        IReadOnlyList<ScanHistoryIssue> issues,
        string? errorMessage)
    {
        Validate(id, targetPath, startedUtc, completedUtc);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(issues);

        return new ScanHistoryRecord(
            id,
            targetKind,
            targetPath,
            recursive,
            startedUtc,
            completedUtc,
            outcome,
            files,
            issues,
            errorMessage);
    }

    private static void Validate(
        Guid id,
        string targetPath,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A non-empty scan ID is required.", nameof(id));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        if (completedUtc < startedUtc)
        {
            throw new ArgumentOutOfRangeException(
                nameof(completedUtc),
                "Completion time cannot precede the start time.");
        }
    }

    private static string? FirstError(FileScanResult result) =>
        result.FileHash.ErrorMessage ??
        result.Reputation?.ErrorMessage ??
        result.Signatures?.ErrorMessage;
}
