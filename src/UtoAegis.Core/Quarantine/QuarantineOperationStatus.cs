namespace UtoAegis.Core.Quarantine;

public enum QuarantineOperationStatus
{
    Quarantined,
    SourceNotFound,
    SourceNotRegularFile,
    IdentityMismatch,
    AccessDenied,
    Failed
}
