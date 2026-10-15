namespace UtoAegis.Cli;

internal readonly record struct FileMetadataSnapshot(long Length, DateTime LastWriteTimeUtc)
{
    public static bool TryCapture(string path, out FileMetadataSnapshot snapshot)
    {
        try
        {
            var file = new FileInfo(Path.GetFullPath(path));
            file.Refresh();
            if (!file.Exists)
            {
                snapshot = default;
                return false;
            }

            snapshot = new FileMetadataSnapshot(file.Length, file.LastWriteTimeUtc);
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            NotSupportedException or
            IOException or
            UnauthorizedAccessException)
        {
            snapshot = default;
            return false;
        }
    }

    public bool Matches(string path) =>
        TryCapture(path, out var current) && current == this;
}
