using UtoAegis.Core.Quarantine;

namespace UtoAegis.Core.Response;

public sealed record ResponseDecision(
    ResponseDecisionKind Kind,
    string? Path,
    string Reason,
    QuarantineOperationResult? QuarantineResult = null)
{
    public bool ChangedSystemState => Kind == ResponseDecisionKind.Quarantined;
}
