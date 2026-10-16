using System.Text.Json;
using UtoAegis.Core.Quarantine;
using UtoAegis.Infrastructure.Quarantine;

namespace UtoAegis.Cli;

internal static class QuarantineCommandRunner
{
    public static async Task<int> ListAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        using var store = await OpenStoreAsync(options.VaultPath!, cancellationToken);
        var entries = await store.ListAsync(options.HistoryLimit, cancellationToken);
        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    vaultPath = Path.GetFullPath(options.VaultPath!),
                    count = entries.Count,
                    entries = entries.Select(CreateEntryPayload)
                },
                CliJson.ResultOptions));
            return ExitCodes.Success;
        }

        if (entries.Count == 0)
        {
            Console.WriteLine("No quarantine entries found.");
            return ExitCodes.Success;
        }

        foreach (var entry in entries)
        {
            Console.WriteLine(
                $"{entry.QuarantinedUtc:O}  {entry.Id:D}  {entry.Status}  " +
                $"{entry.Length} bytes  {entry.OriginalPath}");
        }

        return ExitCodes.Success;
    }

    public static async Task<int> ShowAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        using var store = await OpenStoreAsync(options.VaultPath!, cancellationToken);
        var id = Guid.ParseExact(options.InputPath!, "D");
        var entry = await store.GetAsync(id, cancellationToken);
        if (entry is null)
        {
            Console.Error.WriteLine($"No quarantine entry exists for {id:D}.");
            return ExitCodes.QuarantineFailed;
        }

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                CreateEntryPayload(entry),
                CliJson.ResultOptions));
            return ExitCodes.Success;
        }

        WriteHumanEntry(entry);
        return ExitCodes.Success;
    }

    public static async Task<int> RestoreAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        using var store = await OpenStoreAsync(options.VaultPath!, cancellationToken);
        var id = Guid.ParseExact(options.InputPath!, "D");
        var result = await store.RestoreAsync(
            id,
            options.DestinationPath,
            cancellationToken);
        if (!options.Quiet)
        {
            JsonLogWriter.RestoreFinished(id, result);
        }

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new
                {
                    status = result.Status.ToString(),
                    result.DestinationPath,
                    entry = result.Entry is null ? null : CreateEntryPayload(result.Entry),
                    error = result.ErrorMessage
                },
                CliJson.ResultOptions));
        }
        else if (result.Status == RestoreOperationStatus.Restored)
        {
            Console.WriteLine(
                $"Restored quarantine entry {id:D} to {result.DestinationPath}.");
        }
        else if (result.Status == RestoreOperationStatus.AlreadyRestored)
        {
            Console.WriteLine(
                $"Quarantine entry {id:D} was already restored to {result.DestinationPath}.");
        }
        else
        {
            Console.Error.WriteLine(
                $"Restore failed ({result.Status}): {result.ErrorMessage}");
        }

        return result.Status is RestoreOperationStatus.Restored or
            RestoreOperationStatus.AlreadyRestored
            ? ExitCodes.Success
            : ExitCodes.RestoreFailed;
    }

    internal static object CreateEntryPayload(QuarantineEntry entry) => new
    {
        quarantineId = entry.Id,
        status = entry.Status.ToString(),
        entry.OriginalPath,
        entry.Sha256,
        entry.Length,
        entry.QuarantinedUtc,
        entry.OriginalLastWriteUtc,
        entry.DetectionEvidence,
        entry.RestoredPath,
        entry.RestoredUtc
    };

    private static async ValueTask<FileSystemQuarantineStore> OpenStoreAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var store = new FileSystemQuarantineStore(path);
        try
        {
            await store.InitializeAsync(cancellationToken);
            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    private static void WriteHumanEntry(QuarantineEntry entry)
    {
        Console.WriteLine($"Quarantine ID: {entry.Id:D}");
        Console.WriteLine($"Status: {entry.Status}");
        Console.WriteLine($"Original path: {entry.OriginalPath}");
        Console.WriteLine($"SHA-256: {entry.Sha256}");
        Console.WriteLine($"Length: {entry.Length} bytes");
        Console.WriteLine($"Quarantined: {entry.QuarantinedUtc:O}");
        Console.WriteLine($"Original last write: {entry.OriginalLastWriteUtc:O}");
        Console.WriteLine($"Evidence: {string.Join(", ", entry.DetectionEvidence)}");
        if (entry.RestoredPath is not null)
        {
            Console.WriteLine($"Restore path: {entry.RestoredPath}");
        }

        if (entry.RestoredUtc is not null)
        {
            Console.WriteLine($"Restored: {entry.RestoredUtc:O}");
        }
    }
}
