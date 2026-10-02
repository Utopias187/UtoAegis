namespace UtoAegis.Cli;

internal enum CliCommand
{
    Scan,
    ImportHashes
}

internal sealed record CliOptions(
    CliCommand Command,
    string? InputPath,
    string? DatabasePath,
    bool Json,
    bool Quiet,
    bool ShowHelp)
{
    public static bool TryParse(string[] args, out CliOptions? options, out string? error)
    {
        var command = CliCommand.Scan;
        var index = 0;

        if (args.Length > 0 && args[0] == "scan")
        {
            index++;
        }
        else if (args.Length > 0 && args[0] == "import-hashes")
        {
            command = CliCommand.ImportHashes;
            index++;
        }

        var json = false;
        var quiet = false;
        var showHelp = false;
        var parseOptions = true;
        string? databasePath = null;
        string? inputPath = null;

        while (index < args.Length)
        {
            var argument = args[index++];

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

            if (parseOptions && argument == "--database")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--database requires a path.", out options, out error);
                }

                if (databasePath is not null)
                {
                    return Fail("--database may only be supplied once.", out options, out error);
                }

                databasePath = args[index++];
                continue;
            }

            if (parseOptions && argument.StartsWith('-'))
            {
                return Fail($"Unknown option: {argument}", out options, out error);
            }

            if (inputPath is not null)
            {
                return Fail("Exactly one input path is required.", out options, out error);
            }

            inputPath = argument;
        }

        if (!showHelp && inputPath is null)
        {
            var inputName = command == CliCommand.Scan ? "file" : "JSON Lines import file";
            return Fail($"A {inputName} path is required.", out options, out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && databasePath is null)
        {
            return Fail("import-hashes requires --database <path>.", out options, out error);
        }

        options = new CliOptions(command, inputPath, databasePath, json, quiet, showHelp);
        error = null;
        return true;
    }

    private static bool Fail(
        string message,
        out CliOptions? options,
        out string? error)
    {
        options = null;
        error = message;
        return false;
    }
}
