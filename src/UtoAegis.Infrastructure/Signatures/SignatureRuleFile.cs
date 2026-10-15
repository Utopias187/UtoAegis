using UtoAegis.Core.Signatures;

namespace UtoAegis.Infrastructure.Signatures;

public sealed record SignatureRuleFile(
    IReadOnlyList<ByteSignatureRule> Rules,
    int DuplicateCount);
