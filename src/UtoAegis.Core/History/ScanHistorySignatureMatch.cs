namespace UtoAegis.Core.History;

public sealed record ScanHistorySignatureMatch(
    string RuleId,
    string RuleName,
    string Source,
    long Offset,
    int PatternLengthBytes);
