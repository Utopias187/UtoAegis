using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Reputation;

public sealed record FileReputationScanResult(
    FileHashScanResult FileHash,
    HashReputationResult? Reputation);
