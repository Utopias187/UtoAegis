using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class ThreatUpdateManifestTests
{
    private const string Digest =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void Constructor_ValidManifest_NormalizesValues()
    {
        var manifest = CreateManifest();

        Assert.AreEqual(ThreatUpdateManifest.CurrentSchemaVersion, manifest.SchemaVersion);
        Assert.AreEqual(ThreatUpdateManifest.SignatureAlgorithm, manifest.Algorithm);
        Assert.AreEqual("2026.10.17", manifest.Version);
        Assert.AreEqual("release-key-1", manifest.KeyId);
        Assert.AreEqual(TimeSpan.Zero, manifest.PublishedUtc.Offset);
        Assert.AreEqual(ThreatContentKind.HashIndicators, manifest.Contents[0].Kind);
        Assert.AreEqual("indicators.jsonl", manifest.Contents[0].FileName);
        Assert.AreEqual(ThreatContentKind.ByteSignatures, manifest.Contents[1].Kind);
        Assert.AreEqual("signatures.jsonl", manifest.Contents[1].FileName);
    }

    [TestMethod]
    public void Constructor_MissingPayload_RejectsManifest()
    {
        var contents = new[]
        {
            new ThreatContentDescriptor(ThreatContentKind.HashIndicators, Digest, 12)
        };

        Assert.ThrowsExactly<ArgumentException>(() => CreateManifest(contents: contents));
    }

    [TestMethod]
    public void Constructor_DuplicatePayload_RejectsManifest()
    {
        var contents = new[]
        {
            new ThreatContentDescriptor(ThreatContentKind.HashIndicators, Digest, 12),
            new ThreatContentDescriptor(ThreatContentKind.HashIndicators, Digest, 13)
        };

        Assert.ThrowsExactly<ArgumentException>(() => CreateManifest(contents: contents));
    }

    [TestMethod]
    [DataRow("../escape")]
    [DataRow(" leading")]
    [DataRow("trailing-")]
    [DataRow("contains/slash")]
    [DataRow("contains space")]
    public void Constructor_UnsafeVersion_RejectsManifest(string version)
    {
        Assert.ThrowsExactly<ArgumentException>(() => CreateManifest(version: version));
    }

    [TestMethod]
    public void Descriptor_UppercaseDigest_NormalizesDigest()
    {
        var descriptor = new ThreatContentDescriptor(
            ThreatContentKind.HashIndicators,
            Digest.ToUpperInvariant(),
            1);

        Assert.AreEqual(Digest, descriptor.Sha256);
    }

    [TestMethod]
    public void Descriptor_EmptyPayload_RejectsDescriptor()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new ThreatContentDescriptor(ThreatContentKind.HashIndicators, Digest, 0));
    }

    internal static ThreatUpdateManifest CreateManifest(
        long sequence = 7,
        string version = "2026.10.17",
        DateTimeOffset? publishedUtc = null,
        DateTimeOffset? expiresUtc = null,
        IReadOnlyCollection<ThreatContentDescriptor>? contents = null) =>
        new(
            sequence,
            version,
            "release-key-1",
            publishedUtc ?? new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.FromHours(-5)),
            expiresUtc ?? new DateTimeOffset(2026, 10, 24, 12, 0, 0, TimeSpan.FromHours(-5)),
            contents ??
            [
                new ThreatContentDescriptor(ThreatContentKind.ByteSignatures, Digest, 24),
                new ThreatContentDescriptor(ThreatContentKind.HashIndicators, Digest, 12)
            ]);
}
