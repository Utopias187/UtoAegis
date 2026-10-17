using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

internal static class ThreatContentStateFile
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumStateLength = 16 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 8
    };

    public static async ValueTask<ThreatContentState?> ReadAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists)
        {
            return null;
        }

        if (file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length is <= 0 or > MaximumStateLength)
        {
            throw new ThreatUpdateException("The threat-content state file is not valid.");
        }

        try
        {
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
                throw new ThreatUpdateException(
                    "The threat-content state file changed while it was being read.");
            }

            using var json = JsonDocument.Parse(bytes, DocumentOptions);
            EnsureUniqueProperties(json.RootElement);
            var document = json.RootElement.Deserialize<StateDocument>(SerializerOptions) ??
                throw new ThreatUpdateException("The threat-content state file is not valid.");
            if (document.SchemaVersion != CurrentSchemaVersion ||
                document.HighestAcceptedSequence is null ||
                document.Active is null)
            {
                throw new ThreatUpdateException("The threat-content state file is not valid.");
            }

            var active = ParseReference(document.Active);
            var previous = document.Previous is null ? null : ParseReference(document.Previous);
            if (document.HighestAcceptedSequence.Value < active.Sequence ||
                previous is not null && document.HighestAcceptedSequence.Value < previous.Sequence)
            {
                throw new ThreatUpdateException(
                    "The threat-content state sequence is internally inconsistent.");
            }

            return new ThreatContentState(
                active,
                previous,
                document.HighestAcceptedSequence.Value);
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
            JsonException or ArgumentException)
        {
            throw new ThreatUpdateException("The threat-content state file is not valid.", exception);
        }
    }

    public static byte[] Serialize(ThreatContentState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var document = new StateDocument(
            CurrentSchemaVersion,
            ToDocument(state.Active),
            state.Previous is null ? null : ToDocument(state.Previous),
            state.HighestAcceptedSequence);
        return JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
    }

    private static ThreatContentReference ParseReference(ContentReferenceDocument document)
    {
        if (document.Sequence is null)
        {
            throw new ThreatUpdateException("A threat-content state reference is incomplete.");
        }

        var reference = new ThreatContentReference(
            document.DirectoryName!,
            document.Sequence.Value,
            document.Version!);
        if (!string.Equals(
                reference.DirectoryName,
                ThreatContentReference.FormatDirectoryName(reference.Sequence, reference.Version),
                StringComparison.Ordinal))
        {
            throw new ThreatUpdateException(
                "A threat-content state directory name is not canonical.");
        }

        return reference;
    }

    private static ContentReferenceDocument ToDocument(ThreatContentReference reference) =>
        new(reference.DirectoryName, reference.Sequence, reference.Version);

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
                        $"Duplicate state property '{property.Name}' is not allowed.");
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

    private sealed record StateDocument(
        int? SchemaVersion,
        ContentReferenceDocument? Active,
        ContentReferenceDocument? Previous,
        long? HighestAcceptedSequence);

    private sealed record ContentReferenceDocument(
        string? DirectoryName,
        long? Sequence,
        string? Version);
}

internal sealed record ThreatContentState(
    ThreatContentReference Active,
    ThreatContentReference? Previous,
    long HighestAcceptedSequence);

internal sealed record ThreatContentReference
{
    public ThreatContentReference(string directoryName, long sequence, string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        _ = new ThreatUpdateManifest(
            sequence,
            version,
            "validation-key",
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddSeconds(1),
            [
                new ThreatContentDescriptor(
                    ThreatContentKind.HashIndicators,
                    new string('0', 64),
                    1),
                new ThreatContentDescriptor(
                    ThreatContentKind.ByteSignatures,
                    new string('0', 64),
                    1)
            ]);

        DirectoryName = directoryName;
        Sequence = sequence;
        Version = version;
    }

    public string DirectoryName { get; }

    public long Sequence { get; }

    public string Version { get; }

    public static ThreatContentReference FromManifest(ThreatUpdateManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        return new ThreatContentReference(
            FormatDirectoryName(manifest.Sequence, manifest.Version),
            manifest.Sequence,
            manifest.Version);
    }

    public static string FormatDirectoryName(long sequence, string version) =>
        $"{sequence:D20}-{version}";
}
