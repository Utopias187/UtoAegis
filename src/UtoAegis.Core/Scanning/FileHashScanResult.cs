namespace UtoAegis.Core.Scanning;

public sealed record FileHashScanResult
{
    private FileHashScanResult(
        FileHashScanStatus status,
        string? path,
        string? sha256,
        long? fileSizeBytes,
        TimeSpan elapsed,
        string? errorMessage)
    {
        Status = status;
        Path = path;
        Sha256 = sha256;
        FileSizeBytes = fileSizeBytes;
        Elapsed = elapsed;
        ErrorMessage = errorMessage;
    }

    public FileHashScanStatus Status { get; }

    public string? Path { get; }

    public string? Sha256 { get; }

    public long? FileSizeBytes { get; }

    public TimeSpan Elapsed { get; }

    public string? ErrorMessage { get; }

    public bool IsSuccess => Status == FileHashScanStatus.Success;

    internal static FileHashScanResult Success(
        string path,
        string sha256,
        long fileSizeBytes,
        TimeSpan elapsed) =>
        new(
            FileHashScanStatus.Success,
            path,
            sha256,
            fileSizeBytes,
            elapsed,
            errorMessage: null);

    internal static FileHashScanResult Failure(
        FileHashScanStatus status,
        string? path,
        TimeSpan elapsed,
        string errorMessage) =>
        new(
            status,
            path,
            sha256: null,
            fileSizeBytes: null,
            elapsed,
            errorMessage);
}
