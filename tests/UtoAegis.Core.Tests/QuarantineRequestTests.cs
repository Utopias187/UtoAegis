using UtoAegis.Core.Quarantine;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class QuarantineRequestTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void Constructor_NormalizesHashPathAndEvidence()
    {
        var request = new QuarantineRequest(
            "sample.bin",
            Hash.ToUpperInvariant(),
            12,
            ["signature:demo", " hash:feed ", "signature:demo"]);

        Assert.AreEqual(Path.GetFullPath("sample.bin"), request.SourcePath);
        Assert.AreEqual(Hash, request.ExpectedSha256);
        Assert.AreEqual(12L, request.ExpectedLength);
        Assert.HasCount(2, request.DetectionEvidence);
        Assert.AreEqual("hash:feed", request.DetectionEvidence[0]);
        Assert.AreEqual("signature:demo", request.DetectionEvidence[1]);
    }

    [TestMethod]
    public void Constructor_WithoutDetectionEvidence_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new QuarantineRequest("sample.bin", Hash, 12, []));
    }

    [TestMethod]
    public void Constructor_WithInvalidHash_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new QuarantineRequest("sample.bin", "invalid", 12, ["signature:demo"]));
    }

    [TestMethod]
    public void Constructor_WithControlCharacterInEvidence_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new QuarantineRequest("sample.bin", Hash, 12, ["signature:\ndemo"]));
    }
}
