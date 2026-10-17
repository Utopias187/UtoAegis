using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

internal static class ThreatManifestReader
{
    public const int MaximumManifestLength = 64 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 8
    };

    public static ThreatUpdateManifest Read(ReadOnlySpan<byte> manifestBytes)
    {
        if (manifestBytes.IsEmpty || manifestBytes.Length > MaximumManifestLength)
        {
            throw new ThreatUpdateException(
                $"The update manifest must contain 1 to {MaximumManifestLength} bytes.");
        }

        if (manifestBytes.StartsWith(Encoding.UTF8.Preamble))
        {
            throw new ThreatUpdateException("The update manifest must be UTF-8 without a byte-order mark.");
        }

        try
        {
            var json = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true).GetString(manifestBytes);
            using var document = JsonDocument.Parse(json, DocumentOptions);
            EnsureUniqueProperties(document.RootElement);
            var manifestDocument = document.RootElement.Deserialize<ManifestDocument>(SerializerOptions) ??
                throw new ThreatUpdateException("The update manifest must contain a JSON object.");

            if (manifestDocument.SchemaVersion != ThreatUpdateManifest.CurrentSchemaVersion)
            {
                throw new ThreatUpdateException(
                    $"Unsupported manifest schema version '{manifestDocument.SchemaVersion}'.");
            }

            if (!string.Equals(
                    manifestDocument.Algorithm,
                    ThreatUpdateManifest.SignatureAlgorithm,
                    StringComparison.Ordinal))
            {
                throw new ThreatUpdateException("The update manifest uses an unsupported signature algorithm.");
            }

            if (manifestDocument.Sequence is null ||
                manifestDocument.PublishedUtc is null ||
                manifestDocument.ExpiresUtc is null ||
                manifestDocument.Contents is null)
            {
                throw new ThreatUpdateException("The update manifest is missing a required property.");
            }

            var contents = manifestDocument.Contents.Select(ParseContent).ToArray();
            return new ThreatUpdateManifest(
                manifestDocument.Sequence.Value,
                manifestDocument.Version!,
                manifestDocument.KeyId!,
                manifestDocument.PublishedUtc.Value,
                manifestDocument.ExpiresUtc.Value,
                contents);
        }
        catch (ThreatUpdateException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or ArgumentException)
        {
            throw new ThreatUpdateException("The update manifest is not valid.", exception);
        }
    }

    private static ThreatContentDescriptor ParseContent(ContentDocument content)
    {
        var kind = content.Kind switch
        {
            "hash-indicators" => ThreatContentKind.HashIndicators,
            "byte-signatures" => ThreatContentKind.ByteSignatures,
            _ => throw new ThreatUpdateException(
                $"Unsupported threat-content kind '{content.Kind}'.")
        };

        if (content.Length is null)
        {
            throw new ThreatUpdateException("A content descriptor is missing its length.");
        }

        return new ThreatContentDescriptor(kind, content.Sha256!, content.Length.Value);
    }

    private static void EnsureUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new ThreatUpdateException(
                        $"Duplicate JSON property '{property.Name}' is not allowed.");
                }

                EnsureUniqueProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                EnsureUniqueProperties(item);
            }
        }
    }

    private sealed record ManifestDocument(
        int? SchemaVersion,
        string? Algorithm,
        long? Sequence,
        string? Version,
        string? KeyId,
        DateTimeOffset? PublishedUtc,
        DateTimeOffset? ExpiresUtc,
        IReadOnlyList<ContentDocument>? Contents);

    private sealed record ContentDocument(
        string? Kind,
        string? Sha256,
        long? Length);
}
