namespace UtoAegis.Core.Signatures;

public enum SignatureScanStatus
{
    NoMatch,
    Detected,
    InvalidPath,
    FileNotFound,
    NotAFile,
    AccessDenied,
    FileChangedDuringScan,
    IoError
}
