using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed record ThreatContentSnapshot(
    ThreatUpdateManifest Manifest,
    string ContentDirectory,
    string ReputationDatabasePath,
    string SignatureRulesPath);
