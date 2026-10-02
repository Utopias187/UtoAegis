using UtoAegis.Core.Reputation;

namespace UtoAegis.Infrastructure.Importing;

public sealed record IndicatorImportFile(
    IReadOnlyCollection<MalwareHashIndicator> Indicators,
    int DuplicateCount);
