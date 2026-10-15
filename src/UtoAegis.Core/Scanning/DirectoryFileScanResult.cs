namespace UtoAegis.Core.Scanning;

public sealed record DirectoryFileScanResult(
    string Path,
    FileScanResult Result);
