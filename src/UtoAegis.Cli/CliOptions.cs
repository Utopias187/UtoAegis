using System.Globalization;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Cli;

internal enum CliCommand
{
    Scan,
    ScanDirectory,
    ImportHashes
}

internal sealed record CliOptions(
    CliCommand Command,
    string? InputPath,
    string? DatabasePath,
    string? SignaturePath,
    bool Recursive,
    int MaximumConcurrency,
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
        else if (args.Length > 0 && args[0] == "scan-directory")
        {
            command = CliCommand.ScanDirectory;
            index++;
        }

        var json = false;
        var quiet = false;
        var showHelp = false;
        var recursive = false;
        var recursiveSpecified = false;
        var parseOptions = true;
        var maximumConcurrency = DirectoryScanOptions.DefaultMaximumConcurrency;
        var maximumConcurrencySpecified = false;
        string? databasePath = null;
        string? signaturePath = null;
        string? inputPath = null;

        while (index < args.Length)
        {
            var argument = args[index++];

            if (parseOptions && argument == "--")
            {
                parseOptions = false;
                continue;
            }

            if (parseOptions && argument == "--signatures")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--signatures requires a path.", out options, out error);
                }

                if (signaturePath is not null)
                {
                    return Fail("--signatures may only be supplied once.", out options, out error);
                }

                signaturePath = args[index++];
                continue;
            }

            if (parseOptions && argument == "--recursive")
            {
                if (recursiveSpecified)
                {
                    return Fail("--recursive may only be supplied once.", out options, out error);
                }

                recursive = true;
                recursiveSpecified = true;
                continue;
            }

            if (parseOptions && argument == "--max-concurrency")
            {
                if (index >= args.Length ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out maximumConcurrency) ||
                    maximumConcurrency is < 1 or > DirectoryScanOptions.MaximumAllowedConcurrency)
                {
                    return Fail(
                        $"--max-concurrency requires an integer from 1 to {DirectoryScanOptions.MaximumAllowedConcurrency}.",
                        out options,
                        out error);
                }

                if (maximumConcurrencySpecified)
                {
                    return Fail(
                        "--max-concurrency may only be supplied once.",
                        out options,
                        out error);
                }

                index++;
                maximumConcurrencySpecified = true;
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
            var inputName = command switch
            {
                CliCommand.Scan => "file",
                CliCommand.ScanDirectory => "directory",
                _ => "JSON Lines import file"
            };
            return Fail($"A {inputName} path is required.", out options, out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && databasePath is null)
        {
            return Fail("import-hashes requires --database <path>.", out options, out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && signaturePath is not null)
        {
            return Fail(
                "--signatures is only valid with scan or scan-directory.",
                out options,
                out error);
        }

        if (!showHelp && command != CliCommand.ScanDirectory && recursiveSpecified)
        {
            return Fail("--recursive is only valid with scan-directory.", out options, out error);
        }

        if (!showHelp && command != CliCommand.ScanDirectory && maximumConcurrencySpecified)
        {
            return Fail(
                "--max-concurrency is only valid with scan-directory.",
                out options,
                out error);
        }

        options = new CliOptions(
            command,
            inputPath,
            databasePath,
            signaturePath,
            recursive,
            maximumConcurrency,
            json,
            quiet,
            showHelp);
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
