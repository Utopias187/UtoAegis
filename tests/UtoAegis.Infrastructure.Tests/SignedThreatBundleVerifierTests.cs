using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SignedThreatBundleVerifierTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 10, 17, 18, 0, 0, TimeSpan.Zero);

    private string _testDirectory = null!;
    private ECDsa _signingKey = null!;

    [TestInitialize]
    public void Initialize()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
        _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    [TestCleanup]
    public void Cleanup()
    {
        _signingKey.Dispose();
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_ValidBundle_StagesValidatedContent()
    {
        var bundlePath = await CreateBundleAsync();

        var result = await CreateVerifier().VerifyAndStageAsync(
            bundlePath,
            Path.Combine(_testDirectory, "stage"),
            highestAcceptedSequence: 6);

        Assert.AreEqual(7L, result.Manifest.Sequence);
        Assert.HasCount(1, result.Indicators.Indicators);
        Assert.HasCount(1, result.Signatures.Rules);
        Assert.IsTrue(File.Exists(result.ManifestPath));
        Assert.IsTrue(File.Exists(result.IndicatorPath));
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_TamperedManifest_RejectsAndRemovesStage()
    {
        var bundlePath = await CreateBundleAsync();
        var manifestPath = Path.Combine(bundlePath, SignedThreatBundleVerifier.ManifestFileName);
        var manifest = await File.ReadAllTextAsync(manifestPath);
        await File.WriteAllTextAsync(manifestPath, manifest.Replace("2026.10.17", "2026.10.18"));
        var stagePath = Path.Combine(_testDirectory, "stage");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await CreateVerifier().VerifyAndStageAsync(bundlePath, stagePath, 0));

        StringAssert.Contains(exception.Message, "signature");
        Assert.IsFalse(Directory.Exists(stagePath));
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_TamperedPayload_RejectsBundle()
    {
        var bundlePath = await CreateBundleAsync();
        await File.AppendAllTextAsync(Path.Combine(bundlePath, "indicators.jsonl"), "\n");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await CreateVerifier().VerifyAndStageAsync(
                bundlePath,
                Path.Combine(_testDirectory, "stage"),
                0));

        StringAssert.Contains(exception.Message, "signed length");
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_UnknownSigningKey_RejectsBundle()
    {
        var bundlePath = await CreateBundleAsync(keyId: "unknown-key");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await CreateVerifier().VerifyAndStageAsync(
                bundlePath,
                Path.Combine(_testDirectory, "stage"),
                0));

        StringAssert.Contains(exception.Message, "not trusted");
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_NonIncreasingSequence_RejectsBundle()
    {
        var bundlePath = await CreateBundleAsync(sequence: 7);

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await CreateVerifier().VerifyAndStageAsync(
                bundlePath,
                Path.Combine(_testDirectory, "stage"),
                highestAcceptedSequence: 7));

        StringAssert.Contains(exception.Message, nameof(ThreatUpdateRejectionReason.RollbackDetected));
    }

    [TestMethod]
    public async Task VerifyAndStageAsync_UnexpectedFile_RejectsBundle()
    {
        var bundlePath = await CreateBundleAsync();
        await File.WriteAllTextAsync(Path.Combine(bundlePath, "notes.txt"), "unexpected");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await CreateVerifier().VerifyAndStageAsync(
                bundlePath,
                Path.Combine(_testDirectory, "stage"),
                0));

        StringAssert.Contains(exception.Message, "only the four required");
    }

    [TestMethod]
    public void TrustedThreatSigningKey_PrivateKey_RejectsKey()
    {
        var privateKey = _signingKey.ExportPkcs8PrivateKeyPem();

        var exception = Assert.ThrowsExactly<ArgumentException>(() =>
            new TrustedThreatSigningKey("release-key-1", privateKey));

        StringAssert.Contains(exception.Message, "private-key material");
    }

    [TestMethod]
    public async Task TrustStoreFileLoader_PublicKey_LoadsKeyById()
    {
        var path = Path.Combine(_testDirectory, "release-key.pem");
        await File.WriteAllTextAsync(path, _signingKey.ExportSubjectPublicKeyInfoPem());

        var store = await ThreatTrustStoreFileLoader.LoadAsync(
            new Dictionary<string, string> { ["release-key-1"] = path });

        CollectionAssert.Contains(store.KeyIds.ToArray(), "release-key-1");
    }

    private SignedThreatBundleVerifier CreateVerifier()
    {
        var trustedKey = new TrustedThreatSigningKey(
            "release-key-1",
            _signingKey.ExportSubjectPublicKeyInfoPem());
        var timeProvider = new FixedTimeProvider(Now);
        return new SignedThreatBundleVerifier(
            new ThreatTrustStore([trustedKey]),
            timeProvider: timeProvider);
    }

    private async Task<string> CreateBundleAsync(
        long sequence = 7,
        string keyId = "release-key-1")
    {
        var bundlePath = Path.Combine(_testDirectory, "bundle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(bundlePath);
        var indicatorBytes = Encoding.UTF8.GetBytes(
            "{\"sha256\":\"" + new string('a', 64) + "\",\"source\":\"test-feed\"}\n");
        var signatureBytes = Encoding.UTF8.GetBytes(
            "{\"id\":\"test-rule\",\"name\":\"Test Rule\",\"source\":\"test-feed\",\"hexPattern\":\"4D5A900003000000\"}\n");
        await File.WriteAllBytesAsync(Path.Combine(bundlePath, "indicators.jsonl"), indicatorBytes);
        await File.WriteAllBytesAsync(Path.Combine(bundlePath, "signatures.jsonl"), signatureBytes);

        var manifest = new
        {
            schemaVersion = 1,
            algorithm = ThreatUpdateManifest.SignatureAlgorithm,
            sequence,
            version = "2026.10.17",
            keyId,
            publishedUtc = Now.AddHours(-1),
            expiresUtc = Now.AddDays(7),
            contents = new object[]
            {
                new
                {
                    kind = "hash-indicators",
                    sha256 = Convert.ToHexString(SHA256.HashData(indicatorBytes)).ToLowerInvariant(),
                    length = indicatorBytes.LongLength
                },
                new
                {
                    kind = "byte-signatures",
                    sha256 = Convert.ToHexString(SHA256.HashData(signatureBytes)).ToLowerInvariant(),
                    length = signatureBytes.LongLength
                }
            }
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        await File.WriteAllBytesAsync(
            Path.Combine(bundlePath, SignedThreatBundleVerifier.ManifestFileName),
            manifestBytes);
        var detachedSignature = _signingKey.SignData(
            manifestBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        await File.WriteAllTextAsync(
            Path.Combine(bundlePath, SignedThreatBundleVerifier.SignatureFileName),
            Convert.ToBase64String(detachedSignature));
        return bundlePath;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
