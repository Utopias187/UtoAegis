using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;
using UtoAegis.Infrastructure.History;
using UtoAegis.Infrastructure.Monitoring;
using UtoAegis.Infrastructure.Quarantine;
using UtoAegis.Infrastructure.Reputation;
using UtoAegis.Infrastructure.Signatures;

namespace UtoAegis.Service;

internal sealed class ServiceWorker(
    ServiceConfiguration configuration,
    ILoggerFactory loggerFactory) : BackgroundService
{
    private readonly ILogger logger = loggerFactory.CreateLogger<ServiceWorker>();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        FileSystemQuarantineStore? quarantineStore = null;
        try
        {
            var scanner = await CreateScannerAsync(stoppingToken);
            var historyStore = await CreateHistoryStoreAsync(stoppingToken);
            if (configuration.ResponsePolicy.Mode == ResponseMode.Quarantine)
            {
                quarantineStore = new FileSystemQuarantineStore(configuration.VaultPath!);
                await quarantineStore.InitializeAsync(stoppingToken);
            }

            var responseEngine = new DetectionResponseEngine(
                configuration.ResponsePolicy,
                quarantineStore);
            var sink = new ServiceFileMonitorSink(
                loggerFactory.CreateLogger<ServiceFileMonitorSink>(),
                responseEngine,
                historyStore,
                configuration.Recursive);
            var directoryScanner = new DirectoryScanner(
                scanner,
                new DirectoryScanOptions(
                    configuration.Recursive,
                    configuration.MaximumConcurrency,
                    excludedPaths: configuration.OperationalExclusions));
            var monitoringEngine = new FileMonitoringEngine(
                scanner,
                directoryScanner,
                sink,
                new FileMonitorOptions(
                    configuration.DebounceDelay,
                    configuration.RunInitialScan,
                    configuration.OperationalExclusions));

            await using var eventSource = new FileSystemWatcherEventSource(
                configuration.MonitorRoot,
                configuration.Recursive,
                configuration.QueueCapacity,
                configuration.WatcherBufferSize,
                configuration.OperationalExclusions);
            ServiceLog.MonitoringStarted(
                logger,
                configuration.MonitorRoot,
                configuration.ResponsePolicy.Mode);

            var monitorTask = monitoringEngine
                .RunAsync(configuration.MonitorRoot, eventSource, stoppingToken)
                .AsTask();
            while (!monitorTask.IsCompleted)
            {
                var delay = Task.Delay(configuration.HealthInterval, stoppingToken);
                if (await Task.WhenAny(monitorTask, delay) == monitorTask)
                {
                    break;
                }

                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                WriteHealth(sink.Snapshot());
            }

            var summary = await monitorTask;
            WriteHealth(sink.Snapshot());
            ServiceLog.MonitoringStopped(
                logger,
                summary.Elapsed.TotalMilliseconds,
                summary.EventCount,
                summary.FileScanCount,
                summary.RecoveryScanCount,
                summary.IssueCount);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            ServiceLog.MonitoringStopped(logger, 0, 0, 0, 0, 0);
        }
        finally
        {
            quarantineStore?.Dispose();
        }
    }

    private async ValueTask<IFileScanner> CreateScannerAsync(
        CancellationToken cancellationToken)
    {
        IHashReputationStore? reputationStore = null;
        if (configuration.DatabasePath is not null)
        {
            var store = new SqliteHashReputationStore(configuration.DatabasePath);
            await store.InitializeAsync(cancellationToken);
            reputationStore = store;
        }

        ISignatureScanner? signatureScanner = null;
        if (configuration.SignaturePath is not null)
        {
            var ruleFile = await JsonLinesSignatureRuleReader.ReadAsync(
                configuration.SignaturePath,
                cancellationToken);
            signatureScanner = new FixedByteSignatureScanner(ruleFile.Rules);
            ServiceLog.SignatureRulesLoaded(
                logger,
                ruleFile.Rules.Count,
                ruleFile.DuplicateCount);
        }

        return new CompositeFileScanner(
            new Sha256FileHashScanner(),
            reputationStore,
            signatureScanner);
    }

    private async ValueTask<IScanHistoryStore?> CreateHistoryStoreAsync(
        CancellationToken cancellationToken)
    {
        if (configuration.HistoryPath is null)
        {
            return null;
        }

        var store = new SqliteScanHistoryStore(configuration.HistoryPath);
        await store.InitializeAsync(cancellationToken);
        return store;
    }

    private void WriteHealth(ServiceHealthSnapshot snapshot) =>
        ServiceLog.Health(
            logger,
            snapshot.ScannedFileCount,
            snapshot.DetectionCount,
            snapshot.QuarantinedFileCount,
            snapshot.ResponseFailureCount,
            snapshot.MonitorIssueCount,
            snapshot.HistoryFailureCount);
}
