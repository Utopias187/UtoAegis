using System.ComponentModel;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using UtoAegis.Core.Quarantine;

namespace UtoAegis.Infrastructure.Quarantine;

public sealed class FileSystemQuarantineStore : IQuarantineStore, IDisposable
{
    public const int MaximumListLimit = 200;
    public const int MaximumStoredEntries = 100_000;
    private const int BufferSize = 1024 * 1024;
    private const string ManifestFileName = "metadata.json";
    private const string PayloadFileName = "payload.uaq";

    private static readonly JsonSerializerOptions ManifestJsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly string _rootPath;
    private readonly string _entriesPath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileSystemQuarantineStore(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        _rootPath = Path.GetFullPath(rootPath);
        _entriesPath = Path.Combine(_rootPath, "entries");
    }

    public void Dispose() => _gate.Dispose();

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            CreateRestrictedDirectory(_rootPath);
            RejectReparsePoint(_rootPath);
            CreateRestrictedDirectory(_entriesPath);
            RejectReparsePoint(_entriesPath);
            await Task.CompletedTask;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (QuarantineStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new QuarantineStoreException(
                "The quarantine vault could not be initialized.",
                exception);
        }
    }

    public async ValueTask<QuarantineOperationResult> QuarantineAsync(
        QuarantineRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsInsideVault(request.SourcePath))
            {
                return QuarantineFailure(
                    QuarantineOperationStatus.SourceNotRegularFile,
                    "A file already inside the quarantine vault cannot be quarantined.");
            }

            if (!File.Exists(request.SourcePath))
            {
                return QuarantineFailure(
                    QuarantineOperationStatus.SourceNotFound,
                    "The source file does not exist.");
            }

            if ((File.GetAttributes(request.SourcePath) &
                 (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                return QuarantineFailure(
                    QuarantineOperationStatus.SourceNotRegularFile,
                    "Quarantine accepts regular files and does not follow reparse points.");
            }

            return await QuarantineCoreAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return QuarantineFailure(
                QuarantineOperationStatus.AccessDenied,
                "Access to the source file or quarantine vault was denied.");
        }
        catch (FileNotFoundException)
        {
            return QuarantineFailure(
                QuarantineOperationStatus.SourceNotFound,
                "The source file no longer exists.");
        }
        catch (DirectoryNotFoundException)
        {
            return QuarantineFailure(
                QuarantineOperationStatus.SourceNotFound,
                "The source directory no longer exists.");
        }
        catch (Exception exception) when (exception is IOException or Win32Exception or NotSupportedException)
        {
            return QuarantineFailure(QuarantineOperationStatus.Failed, exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<IReadOnlyList<QuarantineEntry>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > MaximumListLimit)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit),
                $"Quarantine list limit must be from 1 to {MaximumListLimit}.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directories = Directory.EnumerateDirectories(_entriesPath)
                .Take(MaximumStoredEntries + 1)
                .ToArray();
            if (directories.Length > MaximumStoredEntries)
            {
                throw new QuarantineStoreException(
                    $"The vault exceeds the supported limit of {MaximumStoredEntries} entries.");
            }

            var entries = new List<QuarantineEntry>();
            foreach (var directory in directories)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var manifestPath = Path.Combine(directory, ManifestFileName);
                if (File.Exists(manifestPath))
                {
                    entries.Add(await ReadManifestAsync(manifestPath, cancellationToken)
                        .ConfigureAwait(false));
                }
            }

            return entries
                .OrderByDescending(entry => entry.QuarantinedUtc)
                .ThenByDescending(entry => entry.Id)
                .Take(limit)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<QuarantineEntry?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var manifestPath = ManifestPath(id);
            return File.Exists(manifestPath)
                ? await ReadManifestAsync(manifestPath, cancellationToken).ConfigureAwait(false)
                : null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<RestoreOperationResult> RestoreAsync(
        Guid id,
        string? destinationPath = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var manifestPath = ManifestPath(id);
            if (!File.Exists(manifestPath))
            {
                return RestoreFailure(RestoreOperationStatus.NotFound, null, "The quarantine ID was not found.");
            }

            var entry = await ReadManifestAsync(manifestPath, cancellationToken).ConfigureAwait(false);
            if (entry.Status == QuarantineEntryStatus.Restored)
            {
                return new RestoreOperationResult(
                    RestoreOperationStatus.AlreadyRestored,
                    entry,
                    entry.RestoredPath,
                    "The quarantine entry has already been restored.");
            }

            var destination = Path.GetFullPath(destinationPath ?? entry.RestoredPath ?? entry.OriginalPath);
            if (IsInsideVault(destination))
            {
                return RestoreFailure(
                    RestoreOperationStatus.Failed,
                    destination,
                    "A quarantined file cannot be restored inside its vault.");
            }

            if (entry.Status == QuarantineEntryStatus.RestorePending && File.Exists(destination))
            {
                if (await FileMatchesAsync(destination, entry, cancellationToken).ConfigureAwait(false))
                {
                    var recovered = WithRestoration(entry, destination, DateTimeOffset.UtcNow);
                    await WriteManifestAsync(manifestPath, recovered, cancellationToken)
                        .ConfigureAwait(false);
                    return new RestoreOperationResult(
                        RestoreOperationStatus.Restored,
                        recovered,
                        destination,
                        null);
                }

                return RestoreFailure(
                    RestoreOperationStatus.DestinationExists,
                    destination,
                    "The pending restore destination exists with different content.");
            }

            if (File.Exists(destination) || Directory.Exists(destination))
            {
                return RestoreFailure(
                    RestoreOperationStatus.DestinationExists,
                    destination,
                    "The restore destination already exists; overwrite is not allowed.");
            }

            var parent = Path.GetDirectoryName(destination);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
            {
                return RestoreFailure(
                    RestoreOperationStatus.Failed,
                    destination,
                    "The restore destination directory does not exist.");
            }

            RejectReparseSegments(parent);
            var payloadPath = PayloadPath(id);
            if (!File.Exists(payloadPath))
            {
                return RestoreFailure(
                    RestoreOperationStatus.PayloadMissing,
                    destination,
                    "The quarantined payload is missing.");
            }

            if (!await FileMatchesAsync(payloadPath, entry, cancellationToken).ConfigureAwait(false))
            {
                return RestoreFailure(
                    RestoreOperationStatus.PayloadCorrupt,
                    destination,
                    "The quarantined payload failed its SHA-256 or length check.");
            }

            var pending = WithRestoration(entry, destination, restoredUtc: null);
            await WriteManifestAsync(manifestPath, pending, cancellationToken).ConfigureAwait(false);
            var temporaryPath = Path.Combine(
                parent,
                $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.utoaegis-restore");
            try
            {
                await CopyFileAsync(payloadPath, temporaryPath, cancellationToken).ConfigureAwait(false);
                File.Move(temporaryPath, destination);
                File.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteUtc.UtcDateTime);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }

            var restored = WithRestoration(entry, destination, DateTimeOffset.UtcNow);
            await WriteManifestAsync(manifestPath, restored, cancellationToken).ConfigureAwait(false);
            return new RestoreOperationResult(
                RestoreOperationStatus.Restored,
                restored,
                destination,
                null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return RestoreFailure(
                RestoreOperationStatus.AccessDenied,
                destinationPath,
                "Access to the payload or restore destination was denied.");
        }
        catch (Exception exception) when (exception is IOException or NotSupportedException)
        {
            return RestoreFailure(RestoreOperationStatus.Failed, destinationPath, exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask<QuarantineOperationResult> QuarantineCoreAsync(
        QuarantineRequest request,
        CancellationToken cancellationToken)
    {
        var id = Guid.NewGuid();
        var entryPath = EntryPath(id);
        var payloadPath = PayloadPath(id);
        var temporaryPayloadPath = Path.Combine(entryPath, $"payload.{Guid.NewGuid():N}.tmp");

        try
        {
            await using var source = OpenSource(request.SourcePath);
            var originalLastWriteUtc = File.GetLastWriteTimeUtc(request.SourcePath);
            var actualHash = Convert.ToHexString(
                    await SHA256.HashDataAsync(source.Stream, cancellationToken).ConfigureAwait(false))
                .ToLowerInvariant();
            var actualLength = source.Stream.Position;
            if (actualLength != request.ExpectedLength ||
                !string.Equals(actualHash, request.ExpectedSha256, StringComparison.Ordinal))
            {
                return QuarantineFailure(
                    QuarantineOperationStatus.IdentityMismatch,
                    "The file no longer matches the detected SHA-256 and length.");
            }

            CreateRestrictedDirectory(entryPath);
            source.Stream.Position = 0;
            await CopyStreamAsync(source.Stream, temporaryPayloadPath, cancellationToken)
                .ConfigureAwait(false);
            File.Move(temporaryPayloadPath, payloadPath);
            RestrictPayload(payloadPath);

            var entry = QuarantineEntry.Restore(
                id,
                QuarantineEntryStatus.Active,
                request.SourcePath,
                actualHash,
                actualLength,
                DateTimeOffset.UtcNow,
                new DateTimeOffset(originalLastWriteUtc, TimeSpan.Zero),
                request.DetectionEvidence);
            await WriteManifestAsync(ManifestPath(id), entry, cancellationToken)
                .ConfigureAwait(false);

            source.MarkForDeletion();
            return new QuarantineOperationResult(
                QuarantineOperationStatus.Quarantined,
                entry,
                null);
        }
        catch
        {
            if (File.Exists(temporaryPayloadPath))
            {
                File.Delete(temporaryPayloadPath);
            }

            if (Directory.Exists(entryPath))
            {
                DeleteEntryDirectory(entryPath);
            }

            throw;
        }
    }

    private static SourceFile OpenSource(string path) =>
        OperatingSystem.IsWindows()
            ? new SourceFile(WindowsQuarantineFile.Open(path))
            : new SourceFile(new FileStream(
                path,
                new FileStreamOptions
                {
                    Mode = FileMode.Open,
                    Access = FileAccess.Read,
                    Share = FileShare.None,
                    Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                    BufferSize = BufferSize
                }), path);

    private static async ValueTask CopyStreamAsync(
        Stream source,
        string destination,
        CancellationToken cancellationToken)
    {
        await using var target = new FileStream(
            destination,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = BufferSize
            });
        await source.CopyToAsync(target, BufferSize, cancellationToken).ConfigureAwait(false);
        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        target.Flush(flushToDisk: true);
    }

    private static async ValueTask CopyFileAsync(
        string source,
        string destination,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(
            source,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await CopyStreamAsync(input, destination, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<bool> FileMatchesAsync(
        string path,
        QuarantineEntry entry,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != entry.Length)
        {
            return false;
        }

        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return string.Equals(
            Convert.ToHexString(hash),
            entry.Sha256,
            StringComparison.OrdinalIgnoreCase);
    }

    private static QuarantineEntry WithRestoration(
        QuarantineEntry entry,
        string destination,
        DateTimeOffset? restoredUtc) =>
        QuarantineEntry.Restore(
            entry.Id,
            restoredUtc is null
                ? QuarantineEntryStatus.RestorePending
                : QuarantineEntryStatus.Restored,
            entry.OriginalPath,
            entry.Sha256,
            entry.Length,
            entry.QuarantinedUtc,
            entry.OriginalLastWriteUtc,
            entry.DetectionEvidence,
            destination,
            restoredUtc);

    private static async ValueTask<QuarantineEntry> ReadManifestAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length > 64 * 1024)
            {
                throw new QuarantineStoreException("A quarantine manifest exceeds 64 KiB.");
            }

            var manifest = await JsonSerializer.DeserializeAsync<Manifest>(
                    stream,
                    ManifestJsonOptions,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new QuarantineStoreException("A quarantine manifest is empty.");
            return QuarantineEntry.Restore(
                manifest.Id,
                manifest.Status,
                manifest.OriginalPath,
                manifest.Sha256,
                manifest.Length,
                manifest.QuarantinedUtc,
                manifest.OriginalLastWriteUtc,
                manifest.DetectionEvidence,
                manifest.RestoredPath,
                manifest.RestoredUtc);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (QuarantineStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException)
        {
            throw new QuarantineStoreException("A quarantine manifest is invalid.", exception);
        }
    }

    private static async ValueTask WriteManifestAsync(
        string path,
        QuarantineEntry entry,
        CancellationToken cancellationToken)
    {
        var manifest = Manifest.FromEntry(entry);
        var temporaryPath = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(
                        stream,
                        manifest,
                        ManifestJsonOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
            RestrictMetadata(path);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void CreateRestrictedDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            CreateRestrictedWindowsDirectory(path);
            return;
        }

        Directory.CreateDirectory(path);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("windows")]
    private static void CreateRestrictedWindowsDirectory(string path)
    {
        var currentUser = WindowsIdentity.GetCurrent().User ??
            throw new QuarantineStoreException("The current Windows identity has no security identifier.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.ExecuteFile,
            InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly,
            AccessControlType.Deny));
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        var directory = Directory.CreateDirectory(path);
        directory.SetAccessControl(security);
    }

    private static void RestrictPayload(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.ReadOnly);
        }
        else
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead);
        }
    }

    private static void RestrictMetadata(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static void DeleteEntryDirectory(string path)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }

        Directory.Delete(path, recursive: true);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new QuarantineStoreException("The quarantine vault cannot be a reparse point.");
        }
    }

    private static void RejectReparseSegments(string directoryPath)
    {
        var root = Path.GetPathRoot(directoryPath)!;
        var relative = Path.GetRelativePath(root, directoryPath);
        var current = root;
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotSupportedException(
                    "Restore destinations cannot traverse reparse points.");
            }
        }
    }

    private bool IsInsideVault(string path)
    {
        var relative = Path.GetRelativePath(_rootPath, Path.GetFullPath(path));
        return relative != ".." &&
            !Path.IsPathRooted(relative) &&
            !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
            !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private string EntryPath(Guid id) => Path.Combine(_entriesPath, id.ToString("N"));

    private string ManifestPath(Guid id) => Path.Combine(EntryPath(id), ManifestFileName);

    private string PayloadPath(Guid id) => Path.Combine(EntryPath(id), PayloadFileName);

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A non-empty quarantine ID is required.", nameof(id));
        }
    }

    private static QuarantineOperationResult QuarantineFailure(
        QuarantineOperationStatus status,
        string message) => new(status, null, message);

    private static RestoreOperationResult RestoreFailure(
        RestoreOperationStatus status,
        string? destination,
        string message) => new(status, null, destination, message);

    private static bool IsStorageException(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or NotSupportedException or
            System.Security.SecurityException;

    private sealed class SourceFile : IAsyncDisposable
    {
        private readonly WindowsQuarantineFile? _windowsFile;
        private readonly string? _portablePath;

        public SourceFile(WindowsQuarantineFile windowsFile)
        {
            _windowsFile = windowsFile;
            Stream = windowsFile.Stream;
        }

        public SourceFile(FileStream stream, string portablePath)
        {
            Stream = stream;
            _portablePath = portablePath;
        }

        public FileStream Stream { get; }

        public void MarkForDeletion()
        {
            if (_windowsFile is not null)
            {
                _windowsFile.MarkForDeletion();
            }
            else
            {
                File.Delete(_portablePath!);
            }
        }

        public ValueTask DisposeAsync()
        {
            if (_windowsFile is not null)
            {
                _windowsFile.Dispose();
            }
            else
            {
                Stream.Dispose();
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed record Manifest(
        Guid Id,
        QuarantineEntryStatus Status,
        string OriginalPath,
        string Sha256,
        long Length,
        DateTimeOffset QuarantinedUtc,
        DateTimeOffset OriginalLastWriteUtc,
        IReadOnlyList<string> DetectionEvidence,
        string? RestoredPath,
        DateTimeOffset? RestoredUtc)
    {
        public static Manifest FromEntry(QuarantineEntry entry) =>
            new(
                entry.Id,
                entry.Status,
                entry.OriginalPath,
                entry.Sha256,
                entry.Length,
                entry.QuarantinedUtc,
                entry.OriginalLastWriteUtc,
                entry.DetectionEvidence,
                entry.RestoredPath,
                entry.RestoredUtc);
    }
}
