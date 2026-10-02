using System.Text.Json;
using UtoAegis.Cli;
using UtoAegis.Core.Scanning;

const int successExitCode = 0;
const int usageErrorExitCode = 2;
const int scanFailedExitCode = 3;
const int cancelledExitCode = 130;

if (!CliOptions.TryParse(args, out var options, out var parseError))
{
    Console.Error.WriteLine(parseError);
    PrintUsage();
    return usageErrorExitCode;
}

if (options!.ShowHelp)
{
    PrintUsage();
    return successExitCode;
}

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

if (!options.Quiet)
{
    JsonLogWriter.ScanStarted(options.FilePath!);
}

try
{
    var scanner = new Sha256FileHashScanner();
    var result = await scanner.ScanAsync(options.FilePath!, cancellation.Token);

    if (!options.Quiet)
    {
        JsonLogWriter.ScanFinished(result);
    }

    if (options.Json)
    {
        Console.WriteLine(JsonSerializer.Serialize(
            new
            {
                status = result.Status.ToString(),
                path = result.Path,
                algorithm = result.IsSuccess ? "SHA-256" : null,
                sha256 = result.Sha256,
                fileSizeBytes = result.FileSizeBytes,
                elapsedMilliseconds = result.Elapsed.TotalMilliseconds,
                error = result.ErrorMessage
            },
            CliJson.ResultOptions));
    }
    else if (result.IsSuccess)
    {
        Console.WriteLine($"{result.Sha256}  {result.Path}");
    }
    else
    {
        Console.Error.WriteLine($"Scan failed ({result.Status}): {result.ErrorMessage}");
    }

    return result.IsSuccess ? successExitCode : scanFailedExitCode;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Scan cancelled.");
    return cancelledExitCode;
}

static void PrintUsage()
{
    Console.WriteLine(
        """
        UtoAegis SHA-256 file scanner

        Usage:
          utoaegis [--json] [--quiet] [--] <file>

        Options:
          --json   Emit the scan result as JSON.
          --quiet  Suppress structured operational logs on stderr.
          --       Treat all following arguments as positional values.
          -h, --help
                   Show this help text.
        """);
}
