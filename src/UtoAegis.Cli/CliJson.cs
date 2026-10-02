using System.Text.Json;

namespace UtoAegis.Cli;

internal static class CliJson
{
    public static JsonSerializerOptions ResultOptions { get; } =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };
}
