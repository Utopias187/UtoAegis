using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Reputation;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class ThreatContentStoreTests
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
    public async Task ApplyAsync_FirstBundle_AtomicallyActivatesDerivedContent()
    {
        var store = CreateStore();
        var bundle = await CreateBundleAsync(7, 'a');

        var active = await store.ApplyAsync(bundle);
        var status = await store.GetStatusAsync();
        var database = new SqliteHashReputationStore(
            active.ReputationDatabasePath,
            pooling: false);
        var lookup = await database.LookupAsync(new string('a', 64));

        Assert.AreEqual(7L, active.Manifest.Sequence);
        Assert.IsTrue(File.Exists(active.SignatureRulesPath));
        Assert.IsTrue(status.HasActiveContent);
        Assert.AreEqual(7L, status.ActiveSequence);
        Assert.AreEqual(7L, status.HighestAcceptedSequence);
        Assert.IsNull(status.PreviousSequence);
        Assert.AreEqual(HashReputationStatus.Malicious, lookup.Status);
        Assert.IsFalse(File.Exists(active.ReputationDatabasePath + "-wal"));
        Assert.IsFalse(File.Exists(active.ReputationDatabasePath + "-shm"));
    }

    [TestMethod]
    public async Task GetStatusAsync_EmptyStore_ReportsNoActiveContent()
    {
        var store = new ThreatContentStore(Path.Combine(_testDirectory, "empty-store"));

        var status = await store.GetStatusAsync();

        Assert.IsFalse(status.HasActiveContent);
        Assert.AreEqual(0L, status.HighestAcceptedSequence);
    }

    [TestMethod]
    public async Task RollbackAsync_PreviousBundle_RestoresContentWithoutLoweringSequenceFloor()
    {
        var store = CreateStore();
        await store.ApplyAsync(await CreateBundleAsync(7, 'a'));
        await store.ApplyAsync(await CreateBundleAsync(8, 'b'));

        var restored = await store.RollbackAsync();
        var status = await store.GetStatusAsync();

        Assert.AreEqual(7L, restored.Manifest.Sequence);
        Assert.AreEqual(7L, status.ActiveSequence);
        Assert.AreEqual(8L, status.PreviousSequence);
        Assert.AreEqual(8L, status.HighestAcceptedSequence);

        var replay = await CreateBundleAsync(8, 'b');
        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await store.ApplyAsync(replay));
        StringAssert.Contains(exception.Message, nameof(ThreatUpdateRejectionReason.RollbackDetected));
    }

    [TestMethod]
    public async Task RollbackAsync_TamperedPreviousBundle_RefusesStateChange()
    {
        var store = CreateStore();
        var first = await store.ApplyAsync(await CreateBundleAsync(7, 'a'));
        await store.ApplyAsync(await CreateBundleAsync(8, 'b'));
        await File.AppendAllTextAsync(
            Path.Combine(first.ContentDirectory, "indicators.jsonl"),
            "\n");

        await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await store.RollbackAsync());
        var status = await store.GetStatusAsync();

        Assert.AreEqual(8L, status.ActiveSequence);
        Assert.AreEqual(7L, status.PreviousSequence);
        Assert.AreEqual(8L, status.HighestAcceptedSequence);
    }

    [TestMethod]
    public async Task RollbackAsync_NoPreviousVersion_RefusesOperation()
    {
        var store = CreateStore();
        await store.ApplyAsync(await CreateBundleAsync(7, 'a'));

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateException>(
            async () => await store.RollbackAsync());

        StringAssert.Contains(exception.Message, "no previous version");
    }

    [TestMethod]
    public async Task GetActiveAsync_ValidState_ReverifiesSignedPayloads()
    {
        var store = CreateStore();
        await store.ApplyAsync(await CreateBundleAsync(7, 'a'));

        var active = await store.GetActiveAsync();

        Assert.AreEqual(7L, active.Manifest.Sequence);
        Assert.IsTrue(File.Exists(active.ReputationDatabasePath));
    }

    [TestMethod]
    public async Task GetActiveReadOnlyAsync_ValidState_DoesNotCreateStagingContent()
    {
        var store = CreateStore();
        await store.ApplyAsync(await CreateBundleAsync(7, 'a'));
        var stagingPath = Path.Combine(_testDirectory, "content-store", "staging");
        var before = Directory.GetFileSystemEntries(stagingPath);

        var active = await store.GetActiveReadOnlyAsync();
        var after = Directory.GetFileSystemEntries(stagingPath);

        Assert.AreEqual(7L, active.Manifest.Sequence);
        Assert.HasCount(0, before);
        Assert.HasCount(0, after);
    }

    private ThreatContentStore CreateStore()
    {
        var trustedKey = new TrustedThreatSigningKey(
            "release-key-1",
            _signingKey.ExportSubjectPublicKeyInfoPem());
        var verifier = new SignedThreatBundleVerifier(
            new ThreatTrustStore([trustedKey]),
            timeProvider: new FixedTimeProvider(Now));
        return new ThreatContentStore(Path.Combine(_testDirectory, "content-store"), verifier);
    }

    private async Task<string> CreateBundleAsync(long sequence, char hashCharacter)
    {
        var bundlePath = Path.Combine(_testDirectory, $"bundle-{sequence}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(bundlePath);
        var indicatorBytes = Encoding.UTF8.GetBytes(
            "{\"sha256\":\"" + new string(hashCharacter, 64) +
            "\",\"source\":\"test-feed\"}\n");
        var signatureBytes = Encoding.UTF8.GetBytes(
            "{\"id\":\"test-rule-" + sequence +
            "\",\"name\":\"Test Rule\",\"source\":\"test-feed\",\"hexPattern\":\"4D5A900003000000\"}\n");
        await File.WriteAllBytesAsync(Path.Combine(bundlePath, "indicators.jsonl"), indicatorBytes);
        await File.WriteAllBytesAsync(Path.Combine(bundlePath, "signatures.jsonl"), signatureBytes);

        var manifest = new
        {
            schemaVersion = 1,
            algorithm = ThreatUpdateManifest.SignatureAlgorithm,
            sequence,
            version = $"2026.10.{sequence}",
            keyId = "release-key-1",
            publishedUtc = Now.AddHours(-1),
            expiresUtc = Now.AddDays(7),
            contents = new object[]
            {
                Content("hash-indicators", indicatorBytes),
                Content("byte-signatures", signatureBytes)
            }
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        await File.WriteAllBytesAsync(
            Path.Combine(bundlePath, SignedThreatBundleVerifier.ManifestFileName),
            manifestBytes);
        var signature = _signingKey.SignData(
            manifestBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        await File.WriteAllTextAsync(
            Path.Combine(bundlePath, SignedThreatBundleVerifier.SignatureFileName),
            Convert.ToBase64String(signature));
        return bundlePath;
    }

    private static object Content(string kind, byte[] payload) => new
    {
        kind,
        sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
        length = payload.LongLength
    };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
