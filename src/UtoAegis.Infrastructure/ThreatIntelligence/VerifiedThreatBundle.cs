using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Importing;
using UtoAegis.Infrastructure.Signatures;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed record VerifiedThreatBundle(
    ThreatUpdateManifest Manifest,
    string StagingDirectory,
    IndicatorImportFile Indicators,
    SignatureRuleFile Signatures)
{
    public string ManifestPath => Path.Combine(StagingDirectory, SignedThreatBundleVerifier.ManifestFileName);

    public string SignaturePath => Path.Combine(StagingDirectory, SignedThreatBundleVerifier.SignatureFileName);

    public string IndicatorPath => Path.Combine(StagingDirectory, "indicators.jsonl");

    public string SignatureRulesPath => Path.Combine(StagingDirectory, "signatures.jsonl");
}
