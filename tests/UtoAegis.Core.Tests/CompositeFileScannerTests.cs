using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class CompositeFileScannerTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public async Task ScanAsync_HashFailure_SkipsRemainingStages()
    {
        var hashResult = FileHashScanResult.Failure(
            FileHashScanStatus.FileNotFound,
            "missing.bin",
            TimeSpan.Zero,
            "missing");
        var reputationStore = new StubReputationStore(HashReputationResult.Unknown());
        var signatureScanner = new StubSignatureScanner(SignatureScanResult.Completed(
            "stub",
            "missing.bin",
            [],
            0,
            TimeSpan.Zero));
        var scanner = new CompositeFileScanner(
            new StubHashScanner(hashResult),
            reputationStore,
            signatureScanner);

        var result = await scanner.ScanAsync("missing.bin");

        Assert.AreSame(hashResult, result.FileHash);
        Assert.IsNull(result.Reputation);
        Assert.IsNull(result.Signatures);
        Assert.IsFalse(result.IsCompleted);
        Assert.AreEqual(0, reputationStore.LookupCount);
        Assert.AreEqual(0, signatureScanner.ScanCount);
    }

    [TestMethod]
    public async Task ScanAsync_MaliciousReputation_ReturnsDetection()
    {
        var indicator = CreateIndicator();
        var scanner = new CompositeFileScanner(
            new StubHashScanner(SuccessfulHash("sample.bin")),
            new StubReputationStore(HashReputationResult.Malicious(
                indicator,
                DateTimeOffset.UtcNow)));

        var result = await scanner.ScanAsync("sample.bin");

        Assert.IsTrue(result.IsCompleted);
        Assert.IsTrue(result.IsDetected);
        Assert.AreEqual(HashReputationStatus.Malicious, result.Reputation!.Status);
        Assert.IsNull(result.Signatures);
    }

    [TestMethod]
    public async Task ScanAsync_SignatureMatch_ReturnsDetection()
    {
        var signatureResult = SignatureScanResult.Completed(
            "stub",
            "sample.bin",
            [new SignatureMatch("demo.rule", "Demo rule", "test", 4, 8)],
            12,
            TimeSpan.Zero);
        var scanner = new CompositeFileScanner(
            new StubHashScanner(SuccessfulHash("sample.bin")),
            signatureScanner: new StubSignatureScanner(signatureResult));

        var result = await scanner.ScanAsync("sample.bin");

        Assert.IsTrue(result.IsCompleted);
        Assert.IsTrue(result.IsDetected);
        Assert.AreSame(signatureResult, result.Signatures);
    }

    [TestMethod]
    public async Task ScanAsync_ReputationFailure_PreservesSignatureResult()
    {
        var signatureResult = SignatureScanResult.Completed(
            "stub",
            "sample.bin",
            [],
            12,
            TimeSpan.Zero);
        var scanner = new CompositeFileScanner(
            new StubHashScanner(SuccessfulHash("sample.bin")),
            new StubReputationStore(HashReputationResult.LookupFailed("unavailable")),
            new StubSignatureScanner(signatureResult));

        var result = await scanner.ScanAsync("sample.bin");

        Assert.IsFalse(result.IsCompleted);
        Assert.IsFalse(result.IsDetected);
        Assert.AreEqual(HashReputationStatus.LookupFailed, result.Reputation!.Status);
        Assert.AreSame(signatureResult, result.Signatures);
    }

    private static FileHashScanResult SuccessfulHash(string path) =>
        FileHashScanResult.Success(path, Hash, 12, TimeSpan.Zero);

    private static MalwareHashIndicator CreateIndicator()
    {
        var created = MalwareHashIndicator.TryCreate(
            Hash,
            ThreatClassification.Malware,
            "test",
            "Demo.Family",
            firstSeenUtc: null,
            out var indicator,
            out var error);
        Assert.IsTrue(created, error);
        return indicator!;
    }

    private sealed class StubHashScanner(FileHashScanResult result) : IFileHashScanner
    {
        public ValueTask<FileHashScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(result);
    }

    private sealed class StubSignatureScanner(SignatureScanResult result) : ISignatureScanner
    {
        public int ScanCount { get; private set; }

        public string EngineName => "stub";

        public ValueTask<SignatureScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            ScanCount++;
            return ValueTask.FromResult(result);
        }
    }

    private sealed class StubReputationStore(HashReputationResult result) : IHashReputationStore
    {
        public int LookupCount { get; private set; }

        public ValueTask InitializeAsync(CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<HashReputationResult> LookupAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            LookupCount++;
            return ValueTask.FromResult(result);
        }

        public ValueTask<HashImportResult> ImportAsync(
            IReadOnlyCollection<MalwareHashIndicator> indicators,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new HashImportResult(0, 0, 0));
    }
}
