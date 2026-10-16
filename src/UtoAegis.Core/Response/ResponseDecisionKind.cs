namespace UtoAegis.Core.Response;

public enum ResponseDecisionKind
{
    NoDetection,
    ScanIncomplete,
    ObserveOnly,
    AllowlistedHash,
    AllowlistedPath,
    RateLimited,
    DryRun,
    Quarantined,
    QuarantineFailed
}
