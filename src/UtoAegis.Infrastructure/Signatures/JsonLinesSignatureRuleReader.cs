using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Infrastructure.Signatures;

public static class JsonLinesSignatureRuleReader
{
    public const long MaximumFileSizeBytes = 16L * 1024 * 1024;
    public const int MaximumLineLength = 8 * 1024;
    public const int MaximumRuleCount = FixedByteSignatureScanner.MaximumRuleCount;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 4
    };

    public static async ValueTask<SignatureRuleFile> ReadAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new SignatureRuleFileException("A non-empty signature rule file path is required.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new SignatureRuleFileException(
                "The signature rule file path is not valid on this system.",
                exception);
        }

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            return await ReadCoreAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SignatureRuleFileException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            throw new SignatureRuleFileException(
                "The signature rule file could not be read.",
                exception);
        }
    }

    private static async ValueTask<SignatureRuleFile> ReadCoreAsync(
        string fullPath,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(fullPath);
        file.Refresh();
        if (!file.Exists)
        {
            throw new SignatureRuleFileException("The signature rule file does not exist.");
        }

        if (file.Length > MaximumFileSizeBytes)
        {
            throw new SignatureRuleFileException(
                $"The signature rule file exceeds the {MaximumFileSizeBytes}-byte limit.");
        }

        var lengthBefore = file.Length;
        var lastWriteBefore = file.LastWriteTimeUtc;
        var rules = new Dictionary<string, ByteSignatureRule>(StringComparer.OrdinalIgnoreCase);
        var duplicateCount = 0;
        var lineNumber = 0;
        long charactersRead = 0;

        await using var stream = new FileStream(
            fullPath,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 64 * 1024
            });
        using var reader = new StreamReader(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 64 * 1024,
            leaveOpen: false);

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            charactersRead += line.Length;
            if (charactersRead > MaximumFileSizeBytes)
            {
                throw new SignatureRuleFileException(
                    "The decoded signature rule data exceeds the permitted size.");
            }

            if (line.Length == 0)
            {
                continue;
            }

            if (line.Length > MaximumLineLength)
            {
                throw Error(lineNumber, $"Line exceeds the {MaximumLineLength}-character limit.");
            }

            var document = ParseDocument(line, lineNumber);
            if (!ByteSignatureRule.TryCreate(
                    document.Id,
                    document.Name,
                    document.Source,
                    document.HexPattern,
                    out var rule,
                    out var validationError))
            {
                throw Error(lineNumber, validationError!);
            }

            if (rules.TryGetValue(rule!.Id, out var existing))
            {
                if (!AreEquivalent(existing, rule))
                {
                    throw Error(
                        lineNumber,
                        $"Rule id '{rule.Id}' has conflicting definitions.");
                }

                duplicateCount++;
                continue;
            }

            rules.Add(rule.Id, rule);
            if (rules.Count > MaximumRuleCount)
            {
                throw new SignatureRuleFileException(
                    $"The rule file exceeds the {MaximumRuleCount}-rule limit.");
            }
        }

        if (rules.Count == 0)
        {
            throw new SignatureRuleFileException(
                "The signature rule file must contain at least one valid rule.");
        }

        file.Refresh();
        if (!file.Exists || file.Length != lengthBefore || file.LastWriteTimeUtc != lastWriteBefore)
        {
            throw new SignatureRuleFileException(
                "The signature rule file changed while it was being read.");
        }

        return new SignatureRuleFile(rules.Values.ToArray(), duplicateCount);
    }

    private static RuleDocument ParseDocument(string line, int lineNumber)
    {
        try
        {
            using var jsonDocument = JsonDocument.Parse(line, DocumentOptions);
            if (jsonDocument.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Error(lineNumber, "Line must contain a signature rule JSON object.");
            }

            var propertyNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in jsonDocument.RootElement.EnumerateObject())
            {
                if (!propertyNames.Add(property.Name))
                {
                    throw Error(
                        lineNumber,
                        $"Duplicate JSON property '{property.Name}' is not allowed.");
                }
            }

            return jsonDocument.RootElement.Deserialize<RuleDocument>(SerializerOptions) ??
                throw Error(lineNumber, "Line must contain a signature rule JSON object.");
        }
        catch (JsonException exception)
        {
            throw Error(lineNumber, "Line is not a valid signature rule JSON object.", exception);
        }
    }

    private static bool AreEquivalent(ByteSignatureRule left, ByteSignatureRule right) =>
        string.Equals(left.Id, right.Id, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Name, right.Name, StringComparison.Ordinal) &&
        string.Equals(left.Source, right.Source, StringComparison.Ordinal) &&
        string.Equals(left.HexPattern, right.HexPattern, StringComparison.Ordinal);

    private static SignatureRuleFileException Error(
        int lineNumber,
        string message,
        Exception? innerException = null)
    {
        var contextualMessage = $"Signature rule line {lineNumber}: {message}";
        return innerException is null
            ? new SignatureRuleFileException(contextualMessage)
            : new SignatureRuleFileException(contextualMessage, innerException);
    }

    private sealed record RuleDocument(
        string? Id,
        string? Name,
        string? Source,
        string? HexPattern);
}
