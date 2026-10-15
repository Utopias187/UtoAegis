using UtoAegis.Cli;

namespace UtoAegis.Cli.Tests;

[TestClass]
public sealed class FileMetadataSnapshotTests
{
    private string _testDirectory = null!;

    [TestInitialize]
    public void CreateTestDirectory()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
    }

    [TestCleanup]
    public void DeleteTestDirectory()
    {
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task Matches_UnchangedFile_ReturnsTrue()
    {
        var path = Path.Combine(_testDirectory, "unchanged.bin");
        await File.WriteAllTextAsync(path, "original content");

        var captured = FileMetadataSnapshot.TryCapture(path, out var snapshot);

        Assert.IsTrue(captured);
        Assert.IsTrue(snapshot.Matches(path));
    }

    [TestMethod]
    public async Task Matches_ChangedFile_ReturnsFalse()
    {
        var path = Path.Combine(_testDirectory, "changed.bin");
        await File.WriteAllTextAsync(path, "original content");
        Assert.IsTrue(FileMetadataSnapshot.TryCapture(path, out var snapshot));

        await File.AppendAllTextAsync(path, " with additional bytes");

        Assert.IsFalse(snapshot.Matches(path));
    }

    [TestMethod]
    public void TryCapture_MissingFile_ReturnsFalse()
    {
        var captured = FileMetadataSnapshot.TryCapture(
            Path.Combine(_testDirectory, "missing.bin"),
            out _);

        Assert.IsFalse(captured);
    }
}
