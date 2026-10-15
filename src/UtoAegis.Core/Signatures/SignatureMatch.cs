namespace UtoAegis.Core.Signatures;

public sealed record SignatureMatch(
    string RuleId,
    string RuleName,
    string Source,
    long Offset,
    int PatternLengthBytes);
