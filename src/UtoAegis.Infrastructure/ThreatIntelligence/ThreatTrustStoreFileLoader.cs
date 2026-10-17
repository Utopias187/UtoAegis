using System.Text;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public static class ThreatTrustStoreFileLoader
{
    public const int MaximumPublicKeyFileLength = 16 * 1024;

    public static async ValueTask<ThreatTrustStore> LoadAsync(
        IReadOnlyDictionary<string, string> keyPaths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyPaths);
        var keys = new List<TrustedThreatSigningKey>(keyPaths.Count);
        foreach (var (keyId, path) in keyPaths)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            var fullPath = Path.GetFullPath(path);
            var file = new FileInfo(fullPath);
            file.Refresh();
            if (!file.Exists ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Length is <= 0 or > MaximumPublicKeyFileLength)
            {
                throw new ThreatUpdateException(
                    $"Trusted public key '{keyId}' is missing, unsafe, or exceeds the size limit.");
            }

            try
            {
                var bytes = new byte[checked((int)file.Length)];
                await using var stream = new FileStream(
                    fullPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 16 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
                if (stream.ReadByte() != -1)
                {
                    throw new ThreatUpdateException(
                        $"Trusted public key '{keyId}' changed while it was being read.");
                }

                var pem = new UTF8Encoding(false, true).GetString(bytes);
                keys.Add(new TrustedThreatSigningKey(keyId, pem));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (ThreatUpdateException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or
                DecoderFallbackException or ArgumentException)
            {
                throw new ThreatUpdateException(
                    $"Trusted public key '{keyId}' could not be loaded.",
                    exception);
            }
        }

        try
        {
            return new ThreatTrustStore(keys);
        }
        catch (ArgumentException exception)
        {
            throw new ThreatUpdateException("The trusted signing-key set is not valid.", exception);
        }
    }
}
