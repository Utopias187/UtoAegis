namespace UtoAegis.Core.Quarantine;

public enum RestoreOperationStatus
{
    Restored,
    NotFound,
    AlreadyRestored,
    DestinationExists,
    PayloadMissing,
    PayloadCorrupt,
    AccessDenied,
    Failed
}
