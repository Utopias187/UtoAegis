using System.Diagnostics;
using System.Security.Cryptography;

namespace UtoAegis.Core.Scanning;

public sealed class Sha256FileHashScanner : IFileHashScanner
{
    private const int DefaultBufferSize = 1024 * 1024;
    private readonly int _bufferSize;

    public Sha256FileHashScanner(int bufferSize = DefaultBufferSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 4096);
        _bufferSize = bufferSize;
    }

    public async ValueTask<FileHashScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(path))
        {
            return Failure(FileHashScanStatus.InvalidPath, null, stopwatch,
                "A non-empty file path is required.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return Failure(FileHashScanStatus.InvalidPath, null, stopwatch,
                "The supplied path is not valid on this system.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (Directory.Exists(fullPath))
        {
            return Failure(FileHashScanStatus.NotAFile, fullPath, stopwatch,
                "The supplied path refers to a directory, not a file.");
        }

        try
        {
            await using var stream = new FileStream(
                fullPath,
                new FileStreamOptions
                {
                    Mode = FileMode.Open,
                    Access = FileAccess.Read,
                    Share = FileShare.Read,
                    Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                    BufferSize = _bufferSize
                });

            var lengthBefore = stream.Length;
            var lastWriteBefore = File.GetLastWriteTimeUtc(fullPath);
            var hash = await SHA256.HashDataAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            var lengthRead = stream.Position;

            var file = new FileInfo(fullPath);
            file.Refresh();
            if (!file.Exists ||
                lengthRead != lengthBefore ||
                file.Length != lengthBefore ||
                file.LastWriteTimeUtc != lastWriteBefore)
            {
                return Failure(FileHashScanStatus.FileChangedDuringScan, fullPath, stopwatch,
                    "The file changed while it was being scanned; no stable hash was returned.");
            }

            stopwatch.Stop();
            return FileHashScanResult.Success(
                fullPath,
                Convert.ToHexString(hash).ToLowerInvariant(),
                lengthRead,
                stopwatch.Elapsed);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(FileHashScanStatus.AccessDenied, fullPath, stopwatch,
                "Access to the file was denied.");
        }
        catch (FileNotFoundException)
        {
            return Failure(FileHashScanStatus.FileNotFound, fullPath, stopwatch,
                "The file no longer exists.");
        }
        catch (DirectoryNotFoundException)
        {
            return Failure(FileHashScanStatus.FileNotFound, fullPath, stopwatch,
                "The file's directory no longer exists.");
        }
        catch (IOException)
        {
            return Failure(FileHashScanStatus.IoError, fullPath, stopwatch,
                "The file could not be read because of an I/O error.");
        }
    }

    private static FileHashScanResult Failure(
        FileHashScanStatus status,
        string? path,
        Stopwatch stopwatch,
        string message)
    {
        stopwatch.Stop();
        return FileHashScanResult.Failure(status, path, stopwatch.Elapsed, message);
    }
}
