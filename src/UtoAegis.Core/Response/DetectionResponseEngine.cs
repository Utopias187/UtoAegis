using UtoAegis.Core.Quarantine;
using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Response;

public sealed class DetectionResponseEngine
{
    private readonly object rateLimitGate = new();
    private readonly Queue<DateTimeOffset> actionTimes = new();
    private readonly IQuarantineStore? quarantineStore;
    private readonly ResponsePolicy policy;
    private readonly TimeProvider timeProvider;

    public DetectionResponseEngine(
        ResponsePolicy policy,
        IQuarantineStore? quarantineStore = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == ResponseMode.Quarantine && quarantineStore is null)
        {
            throw new ArgumentNullException(
                nameof(quarantineStore),
                "Quarantine mode requires a quarantine store.");
        }

        this.policy = policy;
        this.quarantineStore = quarantineStore;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<ResponseDecision> RespondAsync(
        FileScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (!result.IsCompleted)
        {
            return Decision(ResponseDecisionKind.ScanIncomplete, result, "The scan did not complete.");
        }

        if (!result.IsDetected)
        {
            return Decision(ResponseDecisionKind.NoDetection, result, "No detection requires a response.");
        }

        var path = result.FileHash.Path!;
        var sha256 = result.FileHash.Sha256!;
        if (policy.AllowlistedSha256.Contains(sha256))
        {
            return Decision(ResponseDecisionKind.AllowlistedHash, result, "The file hash is allowlisted.");
        }

        if (policy.IsPathAllowlisted(path))
        {
            return Decision(ResponseDecisionKind.AllowlistedPath, result, "The file path is allowlisted.");
        }

        if (policy.Mode == ResponseMode.ObserveOnly)
        {
            return Decision(ResponseDecisionKind.ObserveOnly, result, "Observe-only mode does not change files.");
        }

        if (policy.Mode == ResponseMode.DryRunQuarantine)
        {
            return Decision(ResponseDecisionKind.DryRun, result, "Dry-run mode would quarantine this file.");
        }

        if (!TryReserveAction(timeProvider.GetUtcNow()))
        {
            return Decision(ResponseDecisionKind.RateLimited, result, "The quarantine action rate limit was reached.");
        }

        var request = new QuarantineRequest(
            path,
            sha256,
            result.FileHash.FileSizeBytes!.Value,
            DetectionEvidence.FromFileScan(result));
        var quarantine = await quarantineStore!.QuarantineAsync(request, cancellationToken);
        return new ResponseDecision(
            quarantine.IsSuccess
                ? ResponseDecisionKind.Quarantined
                : ResponseDecisionKind.QuarantineFailed,
            result.Path,
            quarantine.IsSuccess
                ? "The detected file was quarantined."
                : quarantine.ErrorMessage ?? "The quarantine operation failed.",
            quarantine);
    }

    private static ResponseDecision Decision(
        ResponseDecisionKind kind,
        FileScanResult result,
        string reason) =>
        new(kind, result.Path, reason);

    private bool TryReserveAction(DateTimeOffset now)
    {
        lock (rateLimitGate)
        {
            var cutoff = now - policy.RateLimitWindow;
            while (actionTimes.TryPeek(out var actionTime) && actionTime <= cutoff)
            {
                actionTimes.Dequeue();
            }

            if (actionTimes.Count >= policy.MaxActionsPerWindow)
            {
                return false;
            }

            actionTimes.Enqueue(now);
            return true;
        }
    }
}
