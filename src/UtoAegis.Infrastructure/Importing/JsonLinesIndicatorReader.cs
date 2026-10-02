using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Reputation;

namespace UtoAegis.Infrastructure.Importing;

public static class JsonLinesIndicatorReader
{
    public const long MaximumFileSizeBytes = 128L * 1024 * 1024;
    public const int MaximumLineLength = 16 * 1024;
    public const int MaximumIndicatorCount = 250_000;

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

    public static async ValueTask<IndicatorImportFile> ReadAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        file.Refresh();

        if (!file.Exists)
        {
            throw new FileNotFoundException("The indicator import file does not exist.", fullPath);
        }

        if (file.Length > MaximumFileSizeBytes)
        {
            throw new IndicatorImportException(
                $"The indicator import file exceeds the {MaximumFileSizeBytes}-byte limit.");
        }

        var indicators = new Dictionary<string, MalwareHashIndicator>(StringComparer.Ordinal);
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
                throw new IndicatorImportException(
                    "The decoded indicator data exceeds the permitted size.");
            }

            if (line.Length == 0)
            {
                continue;
            }

            if (line.Length > MaximumLineLength)
            {
                throw Error(lineNumber, $"Line exceeds the {MaximumLineLength}-character limit.");
            }

            IndicatorDocument? document;
            try
            {
                using var jsonDocument = JsonDocument.Parse(line, DocumentOptions);
                if (jsonDocument.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw Error(lineNumber, "Line must contain an indicator JSON object.");
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

                document = jsonDocument.RootElement.Deserialize<IndicatorDocument>(SerializerOptions);
            }
            catch (JsonException exception)
            {
                throw Error(lineNumber, "Line is not a valid indicator JSON object.", exception);
            }

            if (document is null)
            {
                throw Error(lineNumber, "Line must contain an indicator JSON object.");
            }

            var classificationText = document.Classification ?? nameof(ThreatClassification.Malware);
            if (!Enum.TryParse<ThreatClassification>(
                    classificationText,
                    ignoreCase: true,
                    out var classification) ||
                classification != ThreatClassification.Malware)
            {
                throw Error(lineNumber, "Classification must be 'Malware'.");
            }

            if (!MalwareHashIndicator.TryCreate(
                    document.Sha256,
                    classification,
                    document.Source,
                    document.MalwareFamily,
                    document.FirstSeenUtc,
                    out var indicator,
                    out var validationError))
            {
                throw Error(lineNumber, validationError!);
            }

            if (indicators.TryGetValue(indicator!.Sha256, out var existing))
            {
                if (existing != indicator)
                {
                    throw Error(
                        lineNumber,
                        "The file contains conflicting metadata for the same SHA-256 digest.");
                }

                duplicateCount++;
                continue;
            }

            indicators.Add(indicator.Sha256, indicator);
            if (indicators.Count > MaximumIndicatorCount)
            {
                throw new IndicatorImportException(
                    $"The import exceeds the {MaximumIndicatorCount}-indicator limit.");
            }
        }

        return new IndicatorImportFile(indicators.Values.ToArray(), duplicateCount);
    }

    private static IndicatorImportException Error(
        int lineNumber,
        string message,
        Exception? innerException = null)
    {
        var contextualMessage = $"Indicator import line {lineNumber}: {message}";
        return innerException is null
            ? new IndicatorImportException(contextualMessage)
            : new IndicatorImportException(contextualMessage, innerException);
    }

    private sealed record IndicatorDocument(
        string? Sha256,
        string? Classification,
        string? Source,
        string? MalwareFamily,
        DateTimeOffset? FirstSeenUtc);
}
