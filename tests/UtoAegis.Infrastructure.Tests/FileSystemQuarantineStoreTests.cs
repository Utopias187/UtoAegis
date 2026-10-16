using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using UtoAegis.Core.Quarantine;
using UtoAegis.Infrastructure.Quarantine;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class FileSystemQuarantineStoreTests
{
    private string _testDirectory = null!;
    private string _vaultPath = null!;

    [TestInitialize]
    public void CreateTestDirectory()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        _vaultPath = Path.Combine(_testDirectory, "vault");
        Directory.CreateDirectory(_testDirectory);
    }

    [TestCleanup]
    public void DeleteTestDirectory()
    {
        if (!Directory.Exists(_testDirectory))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(
                     _testDirectory,
                     "*",
                     SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }

        Directory.Delete(_testDirectory, recursive: true);
    }

    [TestMethod]
    public async Task InitializeAsync_CreatesProtectedVaultStructure()
    {
        using var store = new FileSystemQuarantineStore(_vaultPath);

        await store.InitializeAsync();

        Assert.IsTrue(Directory.Exists(_vaultPath));
        Assert.IsTrue(Directory.Exists(Path.Combine(_vaultPath, "entries")));
        Assert.IsFalse(
            (File.GetAttributes(_vaultPath) & FileAttributes.ReparsePoint) != 0);
        if (OperatingSystem.IsWindows())
        {
            var security = new DirectoryInfo(_vaultPath).GetAccessControl();
            Assert.IsTrue(security.AreAccessRulesProtected);
        }
    }

    [TestMethod]
    public async Task QuarantineAndRestoreAsync_RoundTripsVerifiedFile()
    {
        var sourcePath = Path.Combine(_testDirectory, "detected.bin");
        var content = "harmless quarantine fixture"u8.ToArray();
        await File.WriteAllBytesAsync(sourcePath, content);
        var originalLastWriteUtc = DateTime.UtcNow.AddMinutes(-5);
        File.SetLastWriteTimeUtc(sourcePath, originalLastWriteUtc);
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();

        var quarantined = await store.QuarantineAsync(Request(sourcePath, content));

        Assert.IsTrue(quarantined.IsSuccess);
        Assert.IsNotNull(quarantined.Entry);
        Assert.IsFalse(File.Exists(sourcePath));
        Assert.AreEqual(QuarantineEntryStatus.Active, quarantined.Entry.Status);
        var payloadPath = Path.Combine(
            _vaultPath,
            "entries",
            quarantined.Entry.Id.ToString("N"),
            "payload.uaq");
        Assert.IsTrue(File.Exists(payloadPath));
        Assert.IsTrue((File.GetAttributes(payloadPath) & FileAttributes.ReadOnly) != 0);
        if (OperatingSystem.IsWindows())
        {
            Assert.IsTrue(HasCurrentUserExecuteDeny(payloadPath));
        }

        var restored = await store.RestoreAsync(quarantined.Entry.Id);

        Assert.IsTrue(restored.IsSuccess);
        Assert.IsTrue(File.Exists(sourcePath));
        CollectionAssert.AreEqual(content, await File.ReadAllBytesAsync(sourcePath));
        Assert.AreEqual(QuarantineEntryStatus.Restored, restored.Entry!.Status);
        Assert.AreEqual(sourcePath, restored.DestinationPath);
    }

    [TestMethod]
    public async Task QuarantineAsync_IdentityMismatch_PreservesSourceAndStoresNothing()
    {
        var sourcePath = Path.Combine(_testDirectory, "changed.bin");
        var content = "current content"u8.ToArray();
        await File.WriteAllBytesAsync(sourcePath, content);
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();
        var request = new QuarantineRequest(
            sourcePath,
            new string('a', 64),
            content.Length,
            ["signature:demo"]);

        var result = await store.QuarantineAsync(request);

        Assert.AreEqual(QuarantineOperationStatus.IdentityMismatch, result.Status);
        Assert.IsTrue(File.Exists(sourcePath));
        Assert.IsEmpty(await store.ListAsync(10));
        Assert.IsEmpty(Directory.EnumerateDirectories(Path.Combine(_vaultPath, "entries")));
    }

    [TestMethod]
    public async Task RestoreAsync_ExistingDestination_RefusesOverwrite()
    {
        var sourcePath = Path.Combine(_testDirectory, "detected.bin");
        var alternatePath = Path.Combine(_testDirectory, "existing.bin");
        var content = "quarantine fixture"u8.ToArray();
        await File.WriteAllBytesAsync(sourcePath, content);
        await File.WriteAllTextAsync(alternatePath, "keep me");
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();
        var quarantined = await store.QuarantineAsync(Request(sourcePath, content));

        var result = await store.RestoreAsync(quarantined.Entry!.Id, alternatePath);

        Assert.AreEqual(RestoreOperationStatus.DestinationExists, result.Status);
        Assert.AreEqual("keep me", await File.ReadAllTextAsync(alternatePath));
        Assert.AreEqual(
            QuarantineEntryStatus.Active,
            (await store.GetAsync(quarantined.Entry.Id))!.Status);
    }

    [TestMethod]
    public async Task RestoreAsync_CorruptPayload_IsRejected()
    {
        var sourcePath = Path.Combine(_testDirectory, "detected.bin");
        var content = "quarantine fixture"u8.ToArray();
        await File.WriteAllBytesAsync(sourcePath, content);
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();
        var quarantined = await store.QuarantineAsync(Request(sourcePath, content));
        var payloadPath = Path.Combine(
            _vaultPath,
            "entries",
            quarantined.Entry!.Id.ToString("N"),
            "payload.uaq");
        File.SetAttributes(payloadPath, FileAttributes.Normal);
        await File.WriteAllBytesAsync(payloadPath, new byte[content.Length]);

        var result = await store.RestoreAsync(quarantined.Entry.Id);

        Assert.AreEqual(RestoreOperationStatus.PayloadCorrupt, result.Status);
        Assert.IsFalse(File.Exists(sourcePath));
    }

    [TestMethod]
    public async Task ListAsync_ReturnsNewestEntriesFirst()
    {
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();
        var firstPath = Path.Combine(_testDirectory, "first.bin");
        var secondPath = Path.Combine(_testDirectory, "second.bin");
        var first = "first"u8.ToArray();
        var second = "second"u8.ToArray();
        await File.WriteAllBytesAsync(firstPath, first);
        var firstResult = await store.QuarantineAsync(Request(firstPath, first));
        await Task.Delay(20);
        await File.WriteAllBytesAsync(secondPath, second);
        var secondResult = await store.QuarantineAsync(Request(secondPath, second));

        var entries = await store.ListAsync(1);

        Assert.HasCount(1, entries);
        Assert.AreEqual(secondResult.Entry!.Id, entries[0].Id);
        Assert.AreNotEqual(firstResult.Entry!.Id, entries[0].Id);
    }

    [TestMethod]
    public async Task RestoreAsync_PendingRestoreWithMatchingDestination_FinalizesRecovery()
    {
        var sourcePath = Path.Combine(_testDirectory, "detected.bin");
        var content = "pending restore fixture"u8.ToArray();
        await File.WriteAllBytesAsync(sourcePath, content);
        using var store = new FileSystemQuarantineStore(_vaultPath);
        await store.InitializeAsync();
        var quarantined = await store.QuarantineAsync(Request(sourcePath, content));
        var entryPath = Path.Combine(
            _vaultPath,
            "entries",
            quarantined.Entry!.Id.ToString("N"));
        var payloadPath = Path.Combine(entryPath, "payload.uaq");
        var metadataPath = Path.Combine(entryPath, "metadata.json");
        File.Copy(payloadPath, sourcePath);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(metadataPath))!.AsObject();
        manifest["status"] = (int)QuarantineEntryStatus.RestorePending;
        manifest["restoredPath"] = sourcePath;
        manifest["restoredUtc"] = null;
        await File.WriteAllTextAsync(metadataPath, manifest.ToJsonString());

        var result = await store.RestoreAsync(quarantined.Entry.Id);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(QuarantineEntryStatus.Restored, result.Entry!.Status);
        Assert.AreEqual(sourcePath, result.DestinationPath);
    }

    private static QuarantineRequest Request(string path, byte[] content) =>
        new(
            path,
            Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
            content.LongLength,
            ["signature:demo"]);

    [SupportedOSPlatform("windows")]
    private static bool HasCurrentUserExecuteDeny(string path)
    {
        var currentUser = WindowsIdentity.GetCurrent().User!;
        var rules = new FileInfo(path)
            .GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>();
        return rules.Any(rule =>
            rule.IdentityReference == currentUser &&
            rule.AccessControlType == AccessControlType.Deny &&
            (rule.FileSystemRights & FileSystemRights.ExecuteFile) != 0);
    }
}
