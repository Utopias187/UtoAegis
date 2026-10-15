using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Monitoring;

public sealed record FileMonitorRecoveryResult(
    MonitorRecoveryReason Reason,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    DirectoryScanResult Result);
