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
    HistoryPrune,
    QuarantineAdd,
    QuarantineList,
    QuarantineShow,
    QuarantineRestore,
    UpdateApply,
    UpdateStatus,
    UpdateRollback
}

internal sealed record CliOptions(
    CliCommand Command,
    string? InputPath,
    string? DatabasePath,
    string? SignaturePath,
    string? HistoryPath,
    string? VaultPath,
    string? DestinationPath,
    string? ContentStorePath,
    IReadOnlyList<string> TrustedKeySpecs,
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
        else if (args.Length > 0 && args[0] == "quarantine")
        {
            if (args.Length < 2)
            {
                return Fail(
                    "quarantine requires a subcommand: add, list, show, or restore.",
                    out options,
                    out error);
            }

            command = args[1] switch
            {
                "add" => CliCommand.QuarantineAdd,
                "list" => CliCommand.QuarantineList,
                "show" => CliCommand.QuarantineShow,
                "restore" => CliCommand.QuarantineRestore,
                _ => (CliCommand)(-1)
            };
            if ((int)command == -1)
            {
                return Fail(
                    $"Unknown quarantine subcommand: {args[1]}",
                    out options,
                    out error);
            }

            index = 2;
        }
        else if (args.Length > 0 && args[0] == "updates")
        {
            if (args.Length < 2)
            {
                return Fail(
                    "updates requires a subcommand: apply, status, or rollback.",
                    out options,
                    out error);
            }

            command = args[1] switch
            {
                "apply" => CliCommand.UpdateApply,
                "status" => CliCommand.UpdateStatus,
                "rollback" => CliCommand.UpdateRollback,
                _ => (CliCommand)(-1)
            };
            if ((int)command == -1)
            {
                return Fail(
                    $"Unknown updates subcommand: {args[1]}",
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
        string? vaultPath = null;
        string? destinationPath = null;
        string? contentStorePath = null;
        var trustedKeySpecs = new List<string>();
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

            if (parseOptions && argument == "--vault")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--vault requires a path.", out options, out error);
                }

                if (vaultPath is not null)
                {
                    return Fail("--vault may only be supplied once.", out options, out error);
                }

                vaultPath = args[index++];
                continue;
            }

            if (parseOptions && argument == "--destination")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--destination requires a path.", out options, out error);
                }

                if (destinationPath is not null)
                {
                    return Fail(
                        "--destination may only be supplied once.",
                        out options,
                        out error);
                }

                destinationPath = args[index++];
                continue;
            }

            if (parseOptions && argument == "--store")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail("--store requires a path.", out options, out error);
                }

                if (contentStorePath is not null)
                {
                    return Fail("--store may only be supplied once.", out options, out error);
                }

                contentStorePath = args[index++];
                continue;
            }

            if (parseOptions && argument == "--trusted-key")
            {
                if (index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                {
                    return Fail(
                        "--trusted-key requires <key-id>=<public-key.pem>.",
                        out options,
                        out error);
                }

                var specification = args[index++];
                var separator = specification.IndexOf('=', StringComparison.Ordinal);
                if (separator <= 0 || separator == specification.Length - 1)
                {
                    return Fail(
                        "--trusted-key requires <key-id>=<public-key.pem>.",
                        out options,
                        out error);
                }

                trustedKeySpecs.Add(specification);
                if (trustedKeySpecs.Count > 32)
                {
                    return Fail(
                        "At most 32 trusted signing keys may be supplied.",
                        out options,
                        out error);
                }

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
            CliCommand.HistoryShow or
            CliCommand.QuarantineAdd or
            CliCommand.QuarantineShow or
            CliCommand.QuarantineRestore or
            CliCommand.UpdateApply;
        if (!showHelp && requiresInput && inputPath is null)
        {
            var inputName = command switch
            {
                CliCommand.Scan => "file",
                CliCommand.ScanDirectory => "directory",
                CliCommand.Monitor => "directory",
                CliCommand.ImportHashes => "JSON Lines import file",
                CliCommand.QuarantineAdd => "file",
                CliCommand.QuarantineShow or CliCommand.QuarantineRestore => "quarantine ID",
                CliCommand.UpdateApply => "signed bundle directory",
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
                "--signatures is only valid with scan, scan-directory, monitor, or quarantine add.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.ImportHashes && historyPath is not null)
        {
            return Fail(
                "--history is only valid with scans, quarantine add, or history commands.",
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

        if (!showHelp && IsQuarantineCommand(command) && vaultPath is null)
        {
            return Fail("Quarantine commands require --vault <path>.", out options, out error);
        }

        if (!showHelp && !IsQuarantineCommand(command) && vaultPath is not null)
        {
            return Fail("--vault is only valid with quarantine commands.", out options, out error);
        }

        if (!showHelp && command != CliCommand.QuarantineRestore && destinationPath is not null)
        {
            return Fail(
                "--destination is only valid with quarantine restore.",
                out options,
                out error);
        }

        if (!showHelp && command == CliCommand.QuarantineAdd &&
            databasePath is null && signaturePath is null)
        {
            return Fail(
                "quarantine add requires --database, --signatures, or both.",
                out options,
                out error);
        }

        if (!showHelp && IsQuarantineManagementCommand(command) &&
            (databasePath is not null || signaturePath is not null || historyPath is not null))
        {
            return Fail(
                "Scan database, signature, and history options are not valid with quarantine management commands.",
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

        if (!showHelp && command is not (CliCommand.HistoryList or CliCommand.QuarantineList) &&
            historyLimitSpecified)
        {
            return Fail(
                "--limit is only valid with history list or quarantine list.",
                out options,
                out error);
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

        if (!showHelp && IsUpdateCommand(command))
        {
            if (contentStorePath is null)
            {
                return Fail("Update commands require --store <path>.", out options, out error);
            }

            if (databasePath is not null || signaturePath is not null || historyPath is not null ||
                vaultPath is not null || destinationPath is not null)
            {
                return Fail(
                    "Scan, history, and quarantine paths are not valid with update commands.",
                    out options,
                    out error);
            }

            if (command is CliCommand.UpdateApply or CliCommand.UpdateRollback &&
                trustedKeySpecs.Count == 0)
            {
                return Fail(
                    "updates apply and rollback require at least one --trusted-key.",
                    out options,
                    out error);
            }

            if (command == CliCommand.UpdateStatus && trustedKeySpecs.Count != 0)
            {
                return Fail(
                    "--trusted-key is not used with updates status.",
                    out options,
                    out error);
            }
        }
        else if (!showHelp && (contentStorePath is not null || trustedKeySpecs.Count != 0))
        {
            return Fail(
                "--store and --trusted-key are only valid with update commands.",
                out options,
                out error);
        }

        if (!showHelp && command is CliCommand.QuarantineShow or CliCommand.QuarantineRestore &&
            !Guid.TryParseExact(inputPath, "D", out _))
        {
            return Fail(
                "quarantine show and restore require an ID in canonical GUID format.",
                out options,
                out error);
        }

        if (!showHelp && command is CliCommand.QuarantineShow or CliCommand.QuarantineRestore)
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
            vaultPath,
            destinationPath,
            contentStorePath,
            trustedKeySpecs,
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

    private static bool IsQuarantineCommand(CliCommand command) =>
        command is CliCommand.QuarantineAdd or
            CliCommand.QuarantineList or
            CliCommand.QuarantineShow or
            CliCommand.QuarantineRestore;

    private static bool IsQuarantineManagementCommand(CliCommand command) =>
        command is CliCommand.QuarantineList or
            CliCommand.QuarantineShow or
            CliCommand.QuarantineRestore;

    private static bool IsUpdateCommand(CliCommand command) =>
        command is CliCommand.UpdateApply or
            CliCommand.UpdateStatus or
            CliCommand.UpdateRollback;

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
