using System.Text.Json;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Cli;

internal static class JsonLogWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static void ScanStarted(string path) => Write(
        "information", "hash_scan_started", path, null, null);

    public static void ScanFinished(FileHashScanResult result) => Write(
        result.IsSuccess ? "information" : "warning",
        result.IsSuccess ? "hash_scan_completed" : "hash_scan_failed",
        result.Path,
        result.Status.ToString(),
        result.Elapsed.TotalMilliseconds);

    private static void Write(
        string level,
        string eventName,
        string? path,
        string? status,
        double? elapsedMilliseconds)
    {
        var logEntry = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level,
            eventName,
            path,
            status,
            elapsedMilliseconds
        };

        Console.Error.WriteLine(JsonSerializer.Serialize(logEntry, SerializerOptions));
    }
}
