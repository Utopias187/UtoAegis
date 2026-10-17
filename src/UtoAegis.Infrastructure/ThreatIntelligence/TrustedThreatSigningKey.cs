using System.Security.Cryptography;
using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class TrustedThreatSigningKey
{
    private const string NistP256Oid = "1.2.840.10045.3.1.7";

    public TrustedThreatSigningKey(string keyId, string publicKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPem);

        ValidateIdentifier(keyId);
        if (publicKeyPem.Contains("PRIVATE KEY", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A trusted signing key must not contain private-key material.",
                nameof(publicKeyPem));
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (!string.Equals(parameters.Curve.Oid.Value, NistP256Oid, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The trusted signing key must use the NIST P-256 curve.",
                    nameof(publicKeyPem));
            }

            KeyId = keyId;
            PublicKeyPem = key.ExportSubjectPublicKeyInfoPem();
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                "The trusted signing key is not a valid ECDSA public key.",
                nameof(publicKeyPem),
                exception);
        }
    }

    public string KeyId { get; }

    public string PublicKeyPem { get; }

    internal bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(PublicKeyPem);
        return key.VerifyData(
            data,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    private static void ValidateIdentifier(string value)
    {
        if (value.Length > ThreatUpdateManifest.MaximumIdentifierLength ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException("The signing key id is not valid.", nameof(value));
        }
    }
}
