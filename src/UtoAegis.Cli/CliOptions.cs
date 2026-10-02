namespace UtoAegis.Cli;

internal sealed record CliOptions(string? FilePath, bool Json, bool Quiet, bool ShowHelp)
{
    public static bool TryParse(string[] args, out CliOptions? options, out string? error)
    {
        var json = false;
        var quiet = false;
        var showHelp = false;
        var parseOptions = true;
        string? filePath = null;

        foreach (var argument in args)
        {
            if (parseOptions && argument == "--")
            {
                parseOptions = false;
                continue;
            }

            if (parseOptions && argument is "--help" or "-h")
            {
                showHelp = true;
                continue;
            }

            if (parseOptions && argument == "--json")
            {
                json = true;
                continue;
            }

            if (parseOptions && argument == "--quiet")
            {
                quiet = true;
                continue;
            }

            if (parseOptions && argument.StartsWith('-'))
            {
                options = null;
                error = $"Unknown option: {argument}";
                return false;
            }

            if (filePath is not null)
            {
                options = null;
                error = "Exactly one file path is required.";
                return false;
            }

            filePath = argument;
        }

        if (!showHelp && filePath is null)
        {
            options = null;
            error = "A file path is required.";
            return false;
        }

        options = new CliOptions(filePath, json, quiet, showHelp);
        error = null;
        return true;
    }
}
