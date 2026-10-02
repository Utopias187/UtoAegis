using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Reputation;

public sealed class FileReputationScanner
{
    private readonly IFileHashScanner _fileHashScanner;
    private readonly IHashReputationStore _reputationStore;

    public FileReputationScanner(
        IFileHashScanner fileHashScanner,
        IHashReputationStore reputationStore)
    {
        _fileHashScanner = fileHashScanner;
        _reputationStore = reputationStore;
    }

    public async ValueTask<FileReputationScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var fileHash = await _fileHashScanner
            .ScanAsync(path, cancellationToken)
            .ConfigureAwait(false);

        if (!fileHash.IsSuccess)
        {
            return new FileReputationScanResult(fileHash, Reputation: null);
        }

        var reputation = await _reputationStore
            .LookupAsync(fileHash.Sha256!, cancellationToken)
            .ConfigureAwait(false);

        return new FileReputationScanResult(fileHash, reputation);
    }
}
