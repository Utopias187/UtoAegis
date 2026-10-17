using System.Security.Cryptography;
using System.Text;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Importing;
using UtoAegis.Infrastructure.Signatures;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class SignedThreatBundleVerifier
{
    public const string ManifestFileName = "manifest.json";
    public const string SignatureFileName = "manifest.sig";
    public const int MaximumSignatureTextLength = 256;

    private static readonly HashSet<string> RequiredFileNames =
        new(StringComparer.Ordinal)
        {
            ManifestFileName,
            SignatureFileName,
            "indicators.jsonl",
            "signatures.jsonl"
        };

    private static readonly HashSet<string> GeneratedDatabaseFileNames =
        new(StringComparer.Ordinal)
        {
            ThreatContentStore.ReputationDatabaseFileName,
            ThreatContentStore.ReputationDatabaseFileName + "-shm",
            ThreatContentStore.ReputationDatabaseFileName + "-wal"
        };

    private readonly ThreatTrustStore _trustStore;
    private readonly ThreatUpdatePolicy _policy;
    private readonly TimeProvider _timeProvider;

    public SignedThreatBundleVerifier(
        ThreatTrustStore trustStore,
        ThreatUpdatePolicy? policy = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);
        _trustStore = trustStore;
        _policy = policy ?? new ThreatUpdatePolicy();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<VerifiedThreatBundle> VerifyAndStageAsync(
        string bundleDirectory,
        string stagingDirectory,
        long highestAcceptedSequence,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(highestAcceptedSequence);
        return await VerifyAndStageCoreAsync(
            bundleDirectory,
            stagingDirectory,
            highestAcceptedSequence,
            expectedSequence: null,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<VerifiedThreatBundle> VerifyInstalledAndStageAsync(
        string bundleDirectory,
        string stagingDirectory,
        long expectedSequence,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedSequence);
        return await VerifyAndStageCoreAsync(
            bundleDirectory,
            stagingDirectory,
            highestAcceptedSequence: null,
            expectedSequence,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<VerifiedThreatBundle> VerifyAndStageCoreAsync(
        string bundleDirectory,
        string stagingDirectory,
        long? highestAcceptedSequence,
        long? expectedSequence,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagingDirectory);

        var bundlePath = Path.GetFullPath(bundleDirectory);
        var stagingPath = Path.GetFullPath(stagingDirectory);
        ValidateBundleDirectory(
            bundlePath,
            allowReputationDatabase: expectedSequence.HasValue);
        if (Directory.Exists(stagingPath) || File.Exists(stagingPath))
        {
            throw new ThreatUpdateException("The staging path must not already exist.");
        }

        Directory.CreateDirectory(stagingPath);
        try
        {
            var manifestBytes = await ReadBoundedFileAsync(
                Path.Combine(bundlePath, ManifestFileName),
                ThreatManifestReader.MaximumManifestLength,
                cancellationToken).ConfigureAwait(false);
            var manifest = ThreatManifestReader.Read(manifestBytes);
            var signature = await ReadSignatureAsync(
                Path.Combine(bundlePath, SignatureFileName),
                cancellationToken).ConfigureAwait(false);

            if (!_trustStore.TryGetKey(manifest.KeyId, out var signingKey))
            {
                throw new ThreatUpdateException(
                    $"The signing key '{manifest.KeyId}' is not trusted.");
            }

            if (!signingKey!.Verify(manifestBytes, signature))
            {
                throw new ThreatUpdateException("The update manifest signature is not valid.");
            }

            if (highestAcceptedSequence.HasValue)
            {
                var acceptance = _policy.Evaluate(
                    manifest,
                    highestAcceptedSequence.Value,
                    _timeProvider.GetUtcNow());
                if (!acceptance.IsAccepted)
                {
                    throw new ThreatUpdateException(
                        $"The update manifest was rejected: {acceptance.RejectionReason}.");
                }
            }
            else if (manifest.Sequence != expectedSequence)
            {
                throw new ThreatUpdateException(
                    "The installed update sequence does not match the content-store state.");
            }

            await File.WriteAllBytesAsync(
                Path.Combine(stagingPath, ManifestFileName),
                manifestBytes,
                cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(
                Path.Combine(stagingPath, SignatureFileName),
                Convert.ToBase64String(signature),
                new UTF8Encoding(false),
                cancellationToken).ConfigureAwait(false);

            foreach (var content in manifest.Contents)
            {
                await CopyAndVerifyPayloadAsync(
                    Path.Combine(bundlePath, content.FileName),
                    Path.Combine(stagingPath, content.FileName),
                    content,
                    cancellationToken).ConfigureAwait(false);
            }

            var indicators = await JsonLinesIndicatorReader.ReadAsync(
                Path.Combine(stagingPath, "indicators.jsonl"),
                cancellationToken).ConfigureAwait(false);
            if (indicators.Indicators.Count == 0)
            {
                throw new ThreatUpdateException(
                    "The hash-indicator payload must contain at least one indicator.");
            }

            var signatures = await JsonLinesSignatureRuleReader.ReadAsync(
                Path.Combine(stagingPath, "signatures.jsonl"),
                cancellationToken).ConfigureAwait(false);
            return new VerifiedThreatBundle(manifest, stagingPath, indicators, signatures);
        }
        catch (OperationCanceledException)
        {
            DeleteStagingDirectory(stagingPath);
            throw;
        }
        catch (ThreatUpdateException)
        {
            DeleteStagingDirectory(stagingPath);
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            CryptographicException or IndicatorImportException or SignatureRuleFileException)
        {
            DeleteStagingDirectory(stagingPath);
            throw new ThreatUpdateException("The signed threat bundle could not be verified.", exception);
        }
    }

    private static void ValidateBundleDirectory(
        string bundlePath,
        bool allowReputationDatabase)
    {
        var directory = new DirectoryInfo(bundlePath);
        directory.Refresh();
        if (!directory.Exists)
        {
            throw new ThreatUpdateException("The signed threat bundle directory does not exist.");
        }

        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new ThreatUpdateException("The signed threat bundle directory cannot be a reparse point.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            if (allowReputationDatabase &&
                entry is FileInfo database &&
                !database.Attributes.HasFlag(FileAttributes.ReparsePoint) &&
                GeneratedDatabaseFileNames.Contains(database.Name))
            {
                continue;
            }

            if (entry is not FileInfo ||
                entry.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                !RequiredFileNames.Contains(entry.Name) ||
                !names.Add(entry.Name))
            {
                throw new ThreatUpdateException(
                    "The signed threat bundle must contain only the four required regular files.");
            }
        }

        if (!names.SetEquals(RequiredFileNames))
        {
            throw new ThreatUpdateException(
                "The signed threat bundle is missing one or more required files.");
        }
    }

    private static async ValueTask<byte[]> ReadBoundedFileAsync(
        string path,
        int maximumLength,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists || file.Length is <= 0 || file.Length > maximumLength)
        {
            throw new ThreatUpdateException(
                $"'{file.Name}' must contain 1 to {maximumLength} bytes.");
        }

        var bytes = new byte[checked((int)file.Length)];
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.ReadByte() != -1)
        {
            throw new ThreatUpdateException($"'{file.Name}' changed while it was being read.");
        }

        return bytes;
    }

    private static async ValueTask<byte[]> ReadSignatureAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedFileAsync(
            path,
            MaximumSignatureTextLength,
            cancellationToken).ConfigureAwait(false);
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new ThreatUpdateException("The manifest signature is not valid UTF-8.", exception);
        }

        var trimmed = text.TrimEnd('\r', '\n');
        if (trimmed.Length == 0 || trimmed.Any(char.IsWhiteSpace))
        {
            throw new ThreatUpdateException("The manifest signature must contain one base64 value.");
        }

        try
        {
            return Convert.FromBase64String(trimmed);
        }
        catch (FormatException exception)
        {
            throw new ThreatUpdateException("The manifest signature is not valid base64.", exception);
        }
    }

    private static async ValueTask CopyAndVerifyPayloadAsync(
        string sourcePath,
        string destinationPath,
        ThreatContentDescriptor content,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long length = 0;
        int bytesRead;
        while ((bytesRead = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            length += bytesRead;
            if (length > content.Length || length > ThreatContentDescriptor.MaximumPayloadLength)
            {
                throw new ThreatUpdateException($"'{content.FileName}' exceeds its signed length.");
            }

            hash.AppendData(buffer.AsSpan(0, bytesRead));
            await destination.WriteAsync(
                buffer.AsMemory(0, bytesRead),
                cancellationToken).ConfigureAwait(false);
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        var actualHash = hash.GetHashAndReset();
        var expectedHash = Convert.FromHexString(content.Sha256);
        if (length != content.Length ||
            !CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
        {
            throw new ThreatUpdateException(
                $"'{content.FileName}' does not match its signed length and SHA-256 digest.");
        }
    }

    private static void DeleteStagingDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
