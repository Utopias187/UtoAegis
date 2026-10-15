using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Cli;

internal static class ExitCodeResolver
{
    public static int ForFile(FileScanResult result)
    {
        if (!result.FileHash.IsSuccess)
        {
            return ExitCodes.ScanFailed;
        }

        if (result.Signatures is { IsCompleted: false })
        {
            return ExitCodes.SignatureScanFailed;
        }

        if (result.IsDetected)
        {
            return ExitCodes.ThreatDetected;
        }

        return result.Reputation?.Status == HashReputationStatus.LookupFailed
            ? ExitCodes.ReputationLookupFailed
            : ExitCodes.Success;
    }

    public static int ForDirectory(DirectoryScanResult result)
    {
        if (!result.IsCompleted)
        {
            return ExitCodes.DirectoryScanFailed;
        }

        if (result.Status == DirectoryScanStatus.Partial)
        {
            return result.HasDetections
                ? ExitCodes.ThreatDetectedWithPartialResults
                : ExitCodes.DirectoryScanPartial;
        }

        return result.HasDetections ? ExitCodes.ThreatDetected : ExitCodes.Success;
    }

    public static int ForHistoryWriteFailure(bool detected) =>
        detected
            ? ExitCodes.ThreatDetectedWithHistoryFailure
            : ExitCodes.HistoryStoreFailed;

    public static int ForOperationFailure(CliCommand command) => command switch
    {
        CliCommand.ScanDirectory => ExitCodes.DirectoryScanFailed,
        CliCommand.Scan => ExitCodes.ScanFailed,
        CliCommand.ImportHashes => ExitCodes.ImportFailed,
        _ => ExitCodes.HistoryStoreFailed
    };
}
