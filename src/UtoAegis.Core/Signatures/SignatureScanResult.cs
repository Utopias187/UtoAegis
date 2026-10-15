namespace UtoAegis.Core.Signatures;

public sealed record SignatureScanResult
{
    private SignatureScanResult(
        string engineName,
        SignatureScanStatus status,
        string? path,
        IReadOnlyList<SignatureMatch> matches,
        long? fileSizeBytes,
        TimeSpan elapsed,
        string? errorMessage)
    {
        EngineName = engineName;
        Status = status;
        Path = path;
        Matches = matches.ToArray();
        FileSizeBytes = fileSizeBytes;
        Elapsed = elapsed;
        ErrorMessage = errorMessage;
    }

    public string EngineName { get; }

    public SignatureScanStatus Status { get; }

    public string? Path { get; }

    public IReadOnlyList<SignatureMatch> Matches { get; }

    public long? FileSizeBytes { get; }

    public TimeSpan Elapsed { get; }

    public string? ErrorMessage { get; }

    public bool IsCompleted => Status is SignatureScanStatus.NoMatch or SignatureScanStatus.Detected;

    public bool IsDetected => Status == SignatureScanStatus.Detected;

    public static SignatureScanResult Completed(
        string engineName,
        string path,
        IReadOnlyList<SignatureMatch> matches,
        long fileSizeBytes,
        TimeSpan elapsed) =>
        new(
            engineName,
            matches.Count == 0 ? SignatureScanStatus.NoMatch : SignatureScanStatus.Detected,
            path,
            matches,
            fileSizeBytes,
            elapsed,
            errorMessage: null);

    public static SignatureScanResult Failure(
        string engineName,
        SignatureScanStatus status,
        string? path,
        TimeSpan elapsed,
        string errorMessage) =>
        new(
            engineName,
            status,
            path,
            [],
            fileSizeBytes: null,
            elapsed,
            errorMessage);
}
