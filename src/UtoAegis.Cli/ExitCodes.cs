namespace UtoAegis.Cli;

internal static class ExitCodes
{
    public const int Success = 0;
    public const int UsageError = 2;
    public const int ScanFailed = 3;
    public const int ReputationLookupFailed = 4;
    public const int ImportFailed = 5;
    public const int ThreatDetected = 10;
    public const int Cancelled = 130;
}
