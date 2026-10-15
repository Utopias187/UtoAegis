namespace UtoAegis.Core.Signatures;

public sealed class ByteSignatureRule
{
    public const int MaximumIdLength = 128;
    public const int MaximumTextLength = 200;
    public const int MinimumPatternLengthBytes = 8;
    public const int MaximumPatternLengthBytes = 1024;

    private readonly byte[] _pattern;

    private ByteSignatureRule(
        string id,
        string name,
        string source,
        byte[] pattern)
    {
        Id = id;
        Name = name;
        Source = source;
        _pattern = pattern;
    }

    public string Id { get; }

    public string Name { get; }

    public string Source { get; }

    public string HexPattern => Convert.ToHexString(_pattern).ToLowerInvariant();

    public int PatternLengthBytes => _pattern.Length;

    internal ReadOnlySpan<byte> Pattern => _pattern;

    public static bool TryCreate(
        string? id,
        string? name,
        string? source,
        string? hexPattern,
        out ByteSignatureRule? rule,
        out string? error)
    {
        var normalizedId = id?.Trim();
        if (!IsValidId(normalizedId))
        {
            return Fail(
                $"Rule id must contain 1 to {MaximumIdLength} ASCII letters, digits, dots, underscores, or hyphens and must start with a letter or digit.",
                out rule,
                out error);
        }

        var normalizedName = name?.Trim();
        if (!IsValidText(normalizedName))
        {
            return Fail(
                $"Rule name must contain 1 to {MaximumTextLength} printable characters.",
                out rule,
                out error);
        }

        var normalizedSource = source?.Trim();
        if (!IsValidText(normalizedSource))
        {
            return Fail(
                $"Rule source must contain 1 to {MaximumTextLength} printable characters.",
                out rule,
                out error);
        }

        if (!TryParsePattern(hexPattern, out var pattern))
        {
            return Fail(
                $"Hex pattern must contain {MinimumPatternLengthBytes} to {MaximumPatternLengthBytes} bytes encoded as hexadecimal without separators.",
                out rule,
                out error);
        }

        rule = new ByteSignatureRule(
            normalizedId!,
            normalizedName!,
            normalizedSource!,
            pattern!);
        error = null;
        return true;
    }

    private static bool TryParsePattern(string? value, out byte[]? pattern)
    {
        var minimumCharacters = MinimumPatternLengthBytes * 2;
        var maximumCharacters = MaximumPatternLengthBytes * 2;
        if (value is null ||
            value.Length < minimumCharacters ||
            value.Length > maximumCharacters ||
            value.Length % 2 != 0)
        {
            pattern = null;
            return false;
        }

        foreach (var character in value)
        {
            var isHexadecimal = character is >= '0' and <= '9' or
                >= 'a' and <= 'f' or
                >= 'A' and <= 'F';
            if (!isHexadecimal)
            {
                pattern = null;
                return false;
            }
        }

        pattern = Convert.FromHexString(value);
        return true;
    }

    private static bool IsValidId(string? value)
    {
        if (value is null || value.Length is 0 or > MaximumIdLength || !IsAsciiAlphaNumeric(value[0]))
        {
            return false;
        }

        return value.All(character =>
            IsAsciiAlphaNumeric(character) || character is '.' or '_' or '-');
    }

    private static bool IsAsciiAlphaNumeric(char value) =>
        value is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';

    private static bool IsValidText(string? value) =>
        value is { Length: > 0 and <= MaximumTextLength } &&
        !value.Any(char.IsControl);

    private static bool Fail(
        string message,
        out ByteSignatureRule? rule,
        out string? error)
    {
        rule = null;
        error = message;
        return false;
    }
}
