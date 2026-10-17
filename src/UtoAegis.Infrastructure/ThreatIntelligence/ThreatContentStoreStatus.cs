namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed record ThreatContentStoreStatus(
    bool HasActiveContent,
    string? ActiveVersion,
    long? ActiveSequence,
    string? PreviousVersion,
    long? PreviousSequence,
    long HighestAcceptedSequence);
