using UtoAegis.Core.Reputation;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Reputation;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatContentStore
{
    public const string StateFileName = "state.json";
    public const string ReputationDatabaseFileName = "reputation.db";

    private readonly string _rootPath;
    private readonly string _versionsPath;
    private readonly string _stagingPath;
    private readonly string _statePath;
    private readonly string _lockPath;
    private readonly SignedThreatBundleVerifier _verifier;

    public ThreatContentStore(string rootPath, SignedThreatBundleVerifier verifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentNullException.ThrowIfNull(verifier);
        _rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));
        if (string.Equals(
                _rootPath,
                Path.TrimEndingDirectorySeparator(Path.GetPathRoot(_rootPath)!),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The threat-content store cannot use a filesystem root.",
                nameof(rootPath));
        }
        _versionsPath = Path.Combine(_rootPath, "versions");
        _stagingPath = Path.Combine(_rootPath, "staging");
        _statePath = Path.Combine(_rootPath, StateFileName);
        _lockPath = Path.Combine(_rootPath, "update.lock");
        _verifier = verifier;
    }

    public async ValueTask<ThreatContentSnapshot> ApplyAsync(
        string bundleDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false);
        var stagePath = CreateStagingPath();
        string? uncommittedVersionPath = null;
        var stateCommitted = false;

        try
        {
            var verified = await _verifier.VerifyAndStageAsync(
                bundleDirectory,
                stagePath,
                state?.HighestAcceptedSequence ?? 0,
                cancellationToken).ConfigureAwait(false);
            await BuildReputationDatabaseAsync(verified, cancellationToken).ConfigureAwait(false);

            var reference = ThreatContentReference.FromManifest(verified.Manifest);
            var finalPath = GetVersionPath(reference);
            if (Directory.Exists(finalPath) || File.Exists(finalPath))
            {
                throw new ThreatUpdateException(
                    "The verified threat-content version already exists in the store.");
            }

            Directory.Move(stagePath, finalPath);
            uncommittedVersionPath = finalPath;
            var nextState = new ThreatContentState(
                reference,
                state?.Active,
                verified.Manifest.Sequence);
            await WriteStateAsync(nextState, cancellationToken).ConfigureAwait(false);
            stateCommitted = true;
            return CreateSnapshot(verified.Manifest, finalPath);
        }
        catch (OperationCanceledException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw;
        }
        catch (ThreatUpdateException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ReputationStoreException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw new ThreatUpdateException("The threat update could not be activated.", exception);
        }
    }

    public async ValueTask<ThreatContentSnapshot> GetActiveAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ThreatUpdateException("The threat-content store has no active version.");
        return await ValidateInstalledAsync(state.Active, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<ThreatContentSnapshot> RollbackAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ThreatUpdateException("The threat-content store has no active version.");
        if (state.Previous is null)
        {
            throw new ThreatUpdateException(
                "The threat-content store has no previous version to restore.");
        }

        var snapshot = await ValidateInstalledAsync(state.Previous, cancellationToken)
            .ConfigureAwait(false);
        var nextState = new ThreatContentState(
            state.Previous,
            state.Active,
            state.HighestAcceptedSequence);
        await WriteStateAsync(nextState, cancellationToken).ConfigureAwait(false);
        return snapshot;
    }

    public async ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false);
        return state is null
            ? new ThreatContentStoreStatus(false, null, null, null, null, 0)
            : new ThreatContentStoreStatus(
                true,
                state.Active.Version,
                state.Active.Sequence,
                state.Previous?.Version,
                state.Previous?.Sequence,
                state.HighestAcceptedSequence);
    }

    private void PrepareDirectories()
    {
        Directory.CreateDirectory(_rootPath);
        EnsureRegularDirectory(_rootPath);
        Directory.CreateDirectory(_versionsPath);
        EnsureRegularDirectory(_versionsPath);
        Directory.CreateDirectory(_stagingPath);
        EnsureRegularDirectory(_stagingPath);
    }

    private FileStream AcquireOperationLock()
    {
        try
        {
            return new FileStream(
                _lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.None);
        }
        catch (IOException exception)
        {
            throw new ThreatUpdateException(
                "Another threat-content operation is already in progress.",
                exception);
        }
    }

    private async ValueTask<ThreatContentSnapshot> ValidateInstalledAsync(
        ThreatContentReference reference,
        CancellationToken cancellationToken)
    {
        var contentPath = GetVersionPath(reference);
        var verificationPath = CreateStagingPath();
        try
        {
            var verified = await _verifier.VerifyInstalledAndStageAsync(
                contentPath,
                verificationPath,
                reference.Sequence,
                cancellationToken).ConfigureAwait(false);
            var databasePath = Path.Combine(contentPath, ReputationDatabaseFileName);
            if (!File.Exists(databasePath))
            {
                throw new ThreatUpdateException(
                    "The installed threat content is missing its reputation database.");
            }

            var firstIndicator = verified.Indicators.Indicators.First();
            var database = new SqliteHashReputationStore(databasePath, pooling: false);
            var lookup = await database.LookupAsync(firstIndicator.Sha256, cancellationToken)
                .ConfigureAwait(false);
            if (lookup.Status != HashReputationStatus.Malicious)
            {
                throw new ThreatUpdateException(
                    "The installed reputation database does not match the signed indicator feed.");
            }

            return CreateSnapshot(verified.Manifest, contentPath);
        }
        finally
        {
            DeleteOwnedStagingDirectory(verificationPath);
        }
    }

    private static async ValueTask BuildReputationDatabaseAsync(
        VerifiedThreatBundle verified,
        CancellationToken cancellationToken)
    {
        var databasePath = Path.Combine(
            verified.StagingDirectory,
            ReputationDatabaseFileName);
        var database = new SqliteHashReputationStore(databasePath, pooling: false);
        await database.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var import = await database.ImportAsync(
            verified.Indicators.Indicators,
            cancellationToken).ConfigureAwait(false);
        if (import.ProcessedCount != verified.Indicators.Indicators.Count)
        {
            throw new ThreatUpdateException(
                "The staged reputation database did not import the complete signed feed.");
        }

        var firstIndicator = verified.Indicators.Indicators.First();
        var lookup = await database.LookupAsync(firstIndicator.Sha256, cancellationToken)
            .ConfigureAwait(false);
        if (lookup.Status != HashReputationStatus.Malicious)
        {
            throw new ThreatUpdateException(
                "The staged reputation database failed its validation lookup.");
        }

        await database.PrepareForReadOnlyAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteStateAsync(
        ThreatContentState state,
        CancellationToken cancellationToken)
    {
        var bytes = ThreatContentStateFile.Serialize(state);
        var temporaryPath = Path.Combine(_rootPath, $"state-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(_statePath))
            {
                File.Replace(temporaryPath, _statePath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(temporaryPath, _statePath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private string CreateStagingPath() =>
        Path.Combine(_stagingPath, Guid.NewGuid().ToString("N"));

    private string GetVersionPath(ThreatContentReference reference) =>
        Path.Combine(_versionsPath, reference.DirectoryName);

    private static ThreatContentSnapshot CreateSnapshot(
        ThreatUpdateManifest manifest,
        string contentPath) =>
        new(
            manifest,
            contentPath,
            Path.Combine(contentPath, ReputationDatabaseFileName),
            Path.Combine(contentPath, "signatures.jsonl"));

    private static void EnsureRegularDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new ThreatUpdateException(
                "Threat-content storage directories cannot be reparse points.");
        }
    }

    private void DeleteOwnedStagingDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.Equals(parent, _stagingPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void DeleteUncommittedVersionDirectory(string? path, bool stateCommitted)
    {
        if (stateCommitted || path is null ||
            !string.Equals(
                Path.GetDirectoryName(path),
                _versionsPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
