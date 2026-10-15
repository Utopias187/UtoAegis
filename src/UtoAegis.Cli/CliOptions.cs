using System.Globalization;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Cli;

internal enum CliCommand
{
    Scan,
    ScanDirectory,
    Monitor,
    ImportHashes,
    HistoryList,
    HistoryShow,
    HistoryPrune
}

internal sealed record CliOptions(
    CliCommand Command,
    string? InputPath,
    string? DatabasePath,
    string? SignaturePath,
    string? HistoryPath,
    bool Recursive,
    int MaximumConcurrency,
    int DebounceMilliseconds,
    int MonitorQueueCapacity,
    int HistoryLimit,
    int? OlderThanDays,
    bool Json,
    bool Quiet,
    bool ShowHelp)
{
    public const int DefaultHistoryLimit = 25;
    public const int MaximumHistoryLimit = 200;
    public const int MaximumRetentionDays = 36_500;
    public const int DefaultDebounceMilliseconds = 500;
    public const int MaximumDebounceMilliseconds = 60_000;
    public const int DefaultMonitorQueueCapacity = 4_096;
    public const int MaximumMonitorQueueCapacity = 65_536;

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
        else if (args.Length > 0 && args[0] == "monitor")
        {
            command = CliCommand.Monitor;
            index++;
        }
        else if (args.Length > 0 && args[0] == "history")
        {
            if (args.Length < 2)
            {
                return Fail(
                    "history requires a subcommand: list, show, or prune.",
                    out options,
                    out error);
            }

            command = args[1] switch
            {
                "list" => CliCommand.HistoryList,
                "show" => CliCommand.HistoryShow,
                "prune" => CliCommand.HistoryPrune,
                _ => (CliCommand)(-1)
            };
            if ((int)command == -1)
            {
                return Fail(
                    $"Unknown history subcommand: {args[1]}",
                    out options,
                    out error);
            }

            index = 2;
        }

        var json = false;
        var quiet = false;
        var showHelp = false;
        var recursive = false;
        var recursiveSpecified = false;
        var parseOptions = true;
        var maximumConcurrency = DirectoryScanOptions.DefaultMaximumConcurrency;
        var maximumConcurrencySpecified = false;
        var debounceMilliseconds = DefaultDebounceMilliseconds;
        var debounceSpecified = false;
        var monitorQueueCapacity = DefaultMonitorQueueCapacity;
        var queueCapacitySpecified = false;
        var historyLimit = DefaultHistoryLimit;
        var historyLimitSpecified = false;
        int? olderThanDays = null;
        string? databasePath = null;
        string? signaturePath = null;
        string? historyPath = null;
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

            if (parseOptions && argument == "--history")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--history requires a path.", out options, out error);
                }

                if (historyPath is not null)
                {
                    return Fail("--history may only be supplied once.", out options, out error);
                }

                historyPath = args[index++];
                continue;
            }

            if (parseOptions && argument == "--limit")
            {
                if (index >= args.Length ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out historyLimit) ||
                    historyLimit is < 1 or > MaximumHistoryLimit)
                {
                    return Fail(
                        $"--limit requires an integer from 1 to {MaximumHistoryLimit}.",
                        out options,
                        out error);
                }

                if (historyLimitSpecified)
                {
                    return Fail("--limit may only be supplied once.", out options, out error);
                }

                index++;
                historyLimitSpecified = true;
                continue;
            }

            if (parseOptions && argument == "--older-than-days")
            {
                if (index >= args.Length ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out var parsedDays) ||
                    parsedDays is < 1 or > MaximumRetentionDays)
                {
                    return Fail(
                        $"--older-than-days requires an integer from 1 to {MaximumRetentionDays}.",
                        out options,
                        out error);
                }

                if (olderThanDays is not null)
                {
                    return Fail(
                        "--older-than-days may only be supplied once.",
                        out options,
                        out error);
                }

                index++;
                olderThanDays = parsedDays;
                continue;
            }

            if (parseOptions && argument == "--debounce-ms")
            {
                if (index >= args.Length ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out debounceMilliseconds) ||
                    debounceMilliseconds is < 0 or > MaximumDebounceMilliseconds)
                {
                    return Fail(
                        $"--debounce-ms requires an integer from 0 to {MaximumDebounceMilliseconds}.",
                        out options,
                        out error);
                }

                if (debounceSpecified)
                {
                    return Fail("--debounce-ms may only be supplied once.", out options, out error);
                }

                index++;
                debounceSpecified = true;
                continue;
            }

            if (parseOptions && argument == "--queue-capacity")
            {
                if (index >= args.Length ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out monitorQueueCapacity) ||
                    monitorQueueCapacity is < 1 or > MaximumMonitorQueueCapacity)
                {
                    return Fail(
                        $"--queue-capacity requires an integer from 1 to {MaximumMonitorQueueCapacity}.",
                        out options,
                        out error);
                }

                if (queueCapacitySpecified)
                {
                    return Fail("--queue-capacity may only be supplied once.", out options, out error);
                }

                index++;
                queueCapacitySpecified = true;
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

        var requiresInput = command is CliCommand.Scan or
            CliCommand.ScanDirectory or
            CliCommand.Monitor or
            CliCommand.ImportHashes or
            CliCommand.HistoryShow;
        if (!showHelp && requiresInput && inputPath is null)
        {
            var inputName = command switch
            {
                CliCommand.Scan => "file",
                CliCommand.ScanDirectory => "directory",
                CliCommand.Monitor => "directory",
                CliCommand.ImportHashes => "JSON Lines import file",
                _ => "scan ID"
            };
            return Fail($"A {inputName} path is required.", out options, out error);
        }

        if (!showHelp && !requiresInput && inputPath is not null)
        {
            return Fail("This command does not accept a positional value.", out options, out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && databasePath is null)
        {
            return Fail("import-hashes requires --database <path>.", out options, out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && signaturePath is not null)
        {
            return Fail(
                "--signatures is only valid with scan, scan-directory, or monitor.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && historyPath is not null)
        {
            return Fail(
                "--history is only valid with scans or history commands.",
                out options,
                out error);
        }

        if (!showHelp && IsHistoryCommand(command) && historyPath is null)
        {
            return Fail("History commands require --history <path>.", out options, out error);
        }

        if (!showHelp && IsHistoryCommand(command) &&
            (databasePath is not null || signaturePath is not null))
        {
            return Fail(
                "--database and --signatures are not valid with history commands.",
                out options,
                out error);
        }

        if (!showHelp && command is not (CliCommand.ScanDirectory or CliCommand.Monitor) &&
            recursiveSpecified)
        {
            return Fail(
                "--recursive is only valid with scan-directory or monitor.",
                out options,
                out error);
        }

        if (!showHelp && command is not (CliCommand.ScanDirectory or CliCommand.Monitor) &&
            maximumConcurrencySpecified)
        {
            return Fail(
                "--max-concurrency is only valid with scan-directory or monitor.",
                out options,
                out error);
        }

        if (!showHelp && command != CliCommand.Monitor && debounceSpecified)
        {
            return Fail("--debounce-ms is only valid with monitor.", out options, out error);
        }

        if (!showHelp && command != CliCommand.Monitor && queueCapacitySpecified)
        {
            return Fail("--queue-capacity is only valid with monitor.", out options, out error);
        }

        if (!showHelp && command != CliCommand.HistoryList && historyLimitSpecified)
        {
            return Fail("--limit is only valid with history list.", out options, out error);
        }

        if (!showHelp && command != CliCommand.HistoryPrune && olderThanDays is not null)
        {
            return Fail(
                "--older-than-days is only valid with history prune.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.HistoryPrune && olderThanDays is null)
        {
            return Fail(
                "history prune requires --older-than-days <days>.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.HistoryShow &&
            !Guid.TryParseExact(inputPath, "D", out _))
        {
            return Fail(
                "history show requires a scan ID in canonical GUID format.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.HistoryShow)
        {
            inputPath = Guid.ParseExact(inputPath!, "D")
                .ToString("D", CultureInfo.InvariantCulture);
        }

        options = new CliOptions(
            command,
            inputPath,
            databasePath,
            signaturePath,
            historyPath,
            recursive,
            maximumConcurrency,
            debounceMilliseconds,
            monitorQueueCapacity,
            historyLimit,
            olderThanDays,
            json,
            quiet,
            showHelp);
        error = null;
        return true;
    }

    private static bool IsHistoryCommand(CliCommand command) =>
        command is CliCommand.HistoryList or CliCommand.HistoryShow or CliCommand.HistoryPrune;

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
