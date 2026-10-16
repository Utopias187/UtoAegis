using UtoAegis.Core.Quarantine;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class QuarantineEntryTests
{
    private const string Hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void Restore_ActiveEntryWithRestorationMetadata_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() => QuarantineEntry.Restore(
            Guid.NewGuid(),
            QuarantineEntryStatus.Active,
            "sample.bin",
            Hash,
            12,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            ["signature:demo"],
            "restored.bin",
            DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public void Restore_RestoredEntryRequiresPathAndTimestamp()
    {
        Assert.ThrowsExactly<ArgumentException>(() => QuarantineEntry.Restore(
            Guid.NewGuid(),
            QuarantineEntryStatus.Restored,
            "sample.bin",
            Hash,
            12,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            ["signature:demo"]));
    }

    [TestMethod]
    public void Restore_PendingEntryRequiresPathWithoutTimestamp()
    {
        Assert.ThrowsExactly<ArgumentException>(() => QuarantineEntry.Restore(
            Guid.NewGuid(),
            QuarantineEntryStatus.RestorePending,
            "sample.bin",
            Hash,
            12,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            ["signature:demo"],
            restoredPath: null,
            restoredUtc: null));
    }
}
