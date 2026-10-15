namespace UtoAegis.Core.Scanning;

public enum DirectoryScanStatus
{
    Completed,
    Partial,
    InvalidPath,
    DirectoryNotFound,
    NotADirectory,
    AccessDenied,
    ReparsePointNotAllowed,
    FileLimitExceeded,
    DirectoryLimitExceeded,
    IoError
}
