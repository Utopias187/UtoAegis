using UtoAegis.Core.Quarantine;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Response;

public static class DetectionEvidence
{
    public static IReadOnlyCollection<string> FromFileScan(FileScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var evidence = new List<string>();
        if (result.Reputation?.Status == HashReputationStatus.Malicious)
        {
            evidence.Add("hash-reputation");
        }

        var ruleIds = result.Signatures?.Matches
            .Select(match => match.RuleId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray() ?? [];
        var availableRuleSlots = QuarantineRequest.MaximumEvidenceCount - evidence.Count;
        var includeSummary = ruleIds.Length > availableRuleSlots;
        if (includeSummary)
        {
            availableRuleSlots--;
        }

        evidence.AddRange(ruleIds
            .Take(availableRuleSlots)
            .Select(ruleId => $"signature:{ruleId}"));
        if (includeSummary)
        {
            evidence.Add($"signature-match-count:{ruleIds.Length}");
        }

        return evidence;
    }
}
