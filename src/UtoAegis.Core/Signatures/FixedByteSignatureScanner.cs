using System.Buffers;
using System.Diagnostics;

namespace UtoAegis.Core.Signatures;

public sealed class FixedByteSignatureScanner : ISignatureScanner
{
    public const string Engine = "fixed-byte-v1";
    public const int MaximumRuleCount = 1024;

    private const int DefaultBufferSize = 1024 * 1024;
    private const int MinimumBufferSize = 4096;
    private const int MaximumBufferSize = 16 * 1024 * 1024;

    private readonly ByteSignatureRule[] _rules;
    private readonly int _bufferSize;
    private readonly int _overlapSize;

    public FixedByteSignatureScanner(
        IReadOnlyCollection<ByteSignatureRule> rules,
        int bufferSize = DefaultBufferSize)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, MinimumBufferSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(bufferSize, MaximumBufferSize);

        if (rules.Count is 0 or > MaximumRuleCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(rules),
                $"A scanner requires 1 to {MaximumRuleCount} rules.");
        }

        _rules = rules.ToArray();
        if (_rules.Any(rule => rule is null))
        {
            throw new ArgumentException("Rule collections cannot contain null values.", nameof(rules));
        }

        var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in _rules)
        {
            if (!ruleIds.Add(rule.Id))
            {
                throw new ArgumentException(
                    $"Rule id '{rule.Id}' is duplicated.",
                    nameof(rules));
            }
        }

        _bufferSize = bufferSize;
        _overlapSize = _rules.Max(rule => rule.PatternLengthBytes) - 1;
    }

    public string EngineName => Engine;

    public async ValueTask<SignatureScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(path))
        {
            return Failure(
                SignatureScanStatus.InvalidPath,
                path: null,
                stopwatch,
                "A non-empty file path is required.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return Failure(
                SignatureScanStatus.InvalidPath,
                path: null,
                stopwatch,
                "The supplied path is not valid on this system.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (Directory.Exists(fullPath))
        {
            return Failure(
                SignatureScanStatus.NotAFile,
                fullPath,
                stopwatch,
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
            var matches = await FindMatchesAsync(stream, cancellationToken).ConfigureAwait(false);
            var lengthRead = stream.Position;

            var file = new FileInfo(fullPath);
            file.Refresh();
            if (!file.Exists ||
                lengthRead != lengthBefore ||
                file.Length != lengthBefore ||
                file.LastWriteTimeUtc != lastWriteBefore)
            {
                return Failure(
                    SignatureScanStatus.FileChangedDuringScan,
                    fullPath,
                    stopwatch,
                    "The file changed while it was being scanned; signature results were discarded.");
            }

            stopwatch.Stop();
            return SignatureScanResult.Completed(
                Engine,
                fullPath,
                matches,
                lengthRead,
                stopwatch.Elapsed);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                SignatureScanStatus.AccessDenied,
                fullPath,
                stopwatch,
                "Access to the file was denied.");
        }
        catch (FileNotFoundException)
        {
            return Failure(
                SignatureScanStatus.FileNotFound,
                fullPath,
                stopwatch,
                "The file no longer exists.");
        }
        catch (DirectoryNotFoundException)
        {
            return Failure(
                SignatureScanStatus.FileNotFound,
                fullPath,
                stopwatch,
                "The file's directory no longer exists.");
        }
        catch (IOException)
        {
            return Failure(
                SignatureScanStatus.IoError,
                fullPath,
                stopwatch,
                "The file could not be read because of an I/O error.");
        }
    }

    private async ValueTask<IReadOnlyList<SignatureMatch>> FindMatchesAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(_bufferSize + _overlapSize);
        try
        {
            var matchedRules = new bool[_rules.Length];
            var remainingRuleCount = _rules.Length;
            var matches = new List<SignatureMatch>();
            var overlapCount = 0;
            long totalBytesRead = 0;

            while (true)
            {
                var bytesRead = await stream
                    .ReadAsync(buffer.AsMemory(overlapCount, _bufferSize), cancellationToken)
                    .ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    break;
                }

                var searchLength = overlapCount + bytesRead;
                var searchWindow = buffer.AsSpan(0, searchLength);
                var windowOffset = totalBytesRead - overlapCount;

                if (remainingRuleCount > 0)
                {
                    for (var index = 0; index < _rules.Length; index++)
                    {
                        if (matchedRules[index])
                        {
                            continue;
                        }

                        var rule = _rules[index];
                        var matchOffset = searchWindow.IndexOf(rule.Pattern);
                        if (matchOffset < 0)
                        {
                            continue;
                        }

                        matchedRules[index] = true;
                        remainingRuleCount--;
                        matches.Add(new SignatureMatch(
                            rule.Id,
                            rule.Name,
                            rule.Source,
                            windowOffset + matchOffset,
                            rule.PatternLengthBytes));
                    }
                }

                totalBytesRead += bytesRead;
                overlapCount = Math.Min(_overlapSize, searchLength);
                searchWindow[^overlapCount..].CopyTo(buffer);
            }

            return matches
                .OrderBy(match => match.Offset)
                .ThenBy(match => match.RuleId, StringComparer.Ordinal)
                .ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static SignatureScanResult Failure(
        SignatureScanStatus status,
        string? path,
        Stopwatch stopwatch,
        string message)
    {
        stopwatch.Stop();
        return SignatureScanResult.Failure(Engine, status, path, stopwatch.Elapsed, message);
    }
}
