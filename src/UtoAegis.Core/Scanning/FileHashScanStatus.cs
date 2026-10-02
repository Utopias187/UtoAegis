namespace UtoAegis.Core.Scanning;

public enum FileHashScanStatus
{
    Success,
    InvalidPath,
    FileNotFound,
    NotAFile,
    AccessDenied,
    FileChangedDuringScan,
    IoError
}
