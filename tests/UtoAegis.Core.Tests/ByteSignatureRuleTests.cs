using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class ByteSignatureRuleTests
{
    private const string ValidPattern = "55544F4145474953";

    [TestMethod]
    public void TryCreate_ValidRule_NormalizesTextAndDecodesPattern()
    {
        var created = ByteSignatureRule.TryCreate(
            "  demo.harmless-marker  ",
            "  Harmless marker  ",
            "  test-fixtures  ",
            ValidPattern,
            out var rule,
            out var error);

        Assert.IsTrue(created);
        Assert.IsNull(error);
        Assert.AreEqual("demo.harmless-marker", rule!.Id);
        Assert.AreEqual("Harmless marker", rule.Name);
        Assert.AreEqual("test-fixtures", rule.Source);
        Assert.AreEqual(ValidPattern.ToLowerInvariant(), rule.HexPattern);
        Assert.AreEqual(8, rule.PatternLengthBytes);
    }

    [TestMethod]
    [DataRow(".starts-with-dot")]
    [DataRow("contains space")]
    [DataRow("contains/slash")]
    [DataRow("")]
    public void TryCreate_InvalidId_RejectsRule(string id)
    {
        var created = ByteSignatureRule.TryCreate(
            id,
            "Harmless marker",
            "test-fixtures",
            ValidPattern,
            out var rule,
            out var error);

        Assert.IsFalse(created);
        Assert.IsNull(rule);
        StringAssert.Contains(error, "Rule id");
    }

    [TestMethod]
    [DataRow("00")]
    [DataRow("55544F414547495")]
    [DataRow("55544F41454749ZZ")]
    [DataRow("55 54 4F 41 45 47 49 53")]
    public void TryCreate_InvalidPattern_RejectsRule(string pattern)
    {
        var created = ByteSignatureRule.TryCreate(
            "demo.harmless-marker",
            "Harmless marker",
            "test-fixtures",
            pattern,
            out var rule,
            out var error);

        Assert.IsFalse(created);
        Assert.IsNull(rule);
        StringAssert.Contains(error, "Hex pattern");
    }

    [TestMethod]
    public void TryCreate_ControlCharacterInSource_RejectsRule()
    {
        var created = ByteSignatureRule.TryCreate(
            "demo.harmless-marker",
            "Harmless marker",
            "unsafe\nsource",
            ValidPattern,
            out var rule,
            out _);

        Assert.IsFalse(created);
        Assert.IsNull(rule);
    }
}
