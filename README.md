# UtoAegis

UtoAegis is an incrementally developed Windows endpoint-security product. It
currently combines safe SHA-256 hashing, a versioned local reputation database,
streaming exact-byte signature detection, bounded directory traversal, and
opt-in structured scan history, real-time directory monitoring, and reversible
quarantine. A supervised Windows service adds health and detection events plus
an explicit response policy. It does not execute scanned files, and the service
defaults to observe-only behavior.

Implementation decisions and verification notes are recorded in the
[development journal](docs/development-journal.md).

## Current architecture

- `UtoAegis.Core` contains file, directory, history, monitoring, and quarantine
  contracts, result models, validation, orchestration, and hash, reputation,
  and signature engines. It has no SQLite dependency.
- `UtoAegis.Infrastructure` contains separate SQLite reputation and scan-history
  stores, strict JSON Lines readers, the bounded filesystem event source, and
  the restricted filesystem quarantine vault.
- `UtoAegis.Cli` handles commands, cancellation, structured logs, output, and
  process exit codes.
- `UtoAegis.Service` hosts the monitor under Windows Service Control Manager,
  validates deployment boundaries, emits Event Log health and detection events,
  and applies the configured response policy.

```text
directory -> bounded traversal -> regular file paths -|
single file ------------------------------------------|-> composite file scanner
                                                       |-> SHA-256 -> reputation
                                                       |-> fixed-byte signatures
                                                       |-> one explicit file result
                                                       |-> optional history store
filesystem events -> bounded queue -> debounce --------|
                         | overflow -> recovery directory scan
detection result -> allowlists -> observe / dry run / bounded quarantine
                                         |-> identity recheck -> restricted vault
Windows SCM -> supervised service -> health and detection events
restricted vault -> integrity check -> no-overwrite restore
```

`Unknown` means only that the digest is absent from the configured database. It
must never be interpreted as proof that a file is safe.

## Build and test

Prerequisite: a .NET 10 SDK compatible with the policy in `global.json`.

```powershell
dotnet restore UtoAegis.slnx --locked-mode
dotnet build UtoAegis.slnx --no-restore --configuration Release
dotnet test UtoAegis.slnx --no-build --configuration Release
```

Package versions are managed centrally in `Directory.Packages.props`, and each
project commits a NuGet lock file. Restore audits direct and transitive packages;
known vulnerability advisories fail the build. GitHub Actions repeats the locked
restore, release build, tests, and vulnerability report for every push to `main`
and every pull request.

## File scanning

Hash a file without performing a reputation lookup:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan README.md
```

Import the harmless demonstration feed and scan its matching test file:

```powershell
dotnet run --project src/UtoAegis.Cli -- import-hashes `
  --database data/reputation.db samples/indicators.example.jsonl

dotnet run --project src/UtoAegis.Cli -- scan `
  --database data/reputation.db samples/harmless-test-file.txt
```

The example deliberately classifies a harmless text fixture as malicious. This
tests the match path without requiring real malware. Never merge the sample feed
into a production indicator database.

Add `--json` for machine-readable output or `--quiet` to suppress operational
JSON Lines logs on standard error.

Run the harmless signature example by itself or alongside reputation scanning:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan `
  --signatures samples/signatures.example.jsonl samples/harmless-test-file.txt

dotnet run --project src/UtoAegis.Cli -- scan `
  --database data/reputation.db `
  --signatures samples/signatures.example.jsonl `
  samples/harmless-test-file.txt
```

## Directory scanning

Scan only the regular files immediately inside a directory:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan-directory samples
```

Recursion is opt-in. The same reputation and signature stages can be applied to
every discovered file with bounded parallelism:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan-directory `
  --recursive `
  --max-concurrency 4 `
  --database data/reputation.db `
  --signatures samples/signatures.example.jsonl `
  samples
```

The scanner does not follow reparse points. It discovers a bounded file set,
sorts results deterministically, and continues after individual file failures.
The default limits are 100,000 files, 50,000 directories, a traversal depth of
64, and four concurrent file scans. The library also enforces absolute maxima
of 1,000,000 files, 250,000 directories, depth 256, and concurrency 32.

Configured signature and reputation database files, including SQLite `-wal`
and `-shm` files, are excluded when they are inside the requested directory.
Every exclusion or skipped entry is reported, which makes the overall result
`Partial` instead of implying complete coverage. `--json` returns a structured
summary, issues, and every per-file result.

## Real-time file monitoring

Start the watcher before the initial directory scan, then scan files as they
are created, changed, or renamed:

```powershell
dotnet run --project src/UtoAegis.Cli -- monitor `
  --recursive `
  --database data/reputation.db `
  --signatures samples/signatures.example.jsonl `
  --history data/history.db `
  samples
```

The monitor runs until Ctrl+C. Events for the same path are debounced for 500
milliseconds by default, and the managed event queue is capped at 4,096 items.
Use `--debounce-ms` and `--queue-capacity` to tune those limits. Recovery scans
reuse `--max-concurrency`, whose default is four.

Both the operating-system watcher buffer and the managed queue can overflow.
An overflow is reported as an issue, pending per-file events are discarded, and
a full directory recovery scan runs so event loss is never treated as complete
coverage. Source errors remain visible but do not silently become detections.
Configured rule, reputation, and history files plus their SQLite sidecars are
excluded at the watcher and scanner boundaries to prevent self-triggering loops.

With `--json`, standard output is a JSON Lines stream containing a separate
`recoveryScan`, `fileScan`, or `monitorIssue` object for each result. Requested
history is appended per scan. Operational JSON Lines logs remain on standard
error and can be suppressed with `--quiet`.

## Windows background service

`UtoAegis.Service` runs the same bounded monitoring pipeline under Windows
Service Control Manager. Configuration is rejected before startup when paths,
queue limits, response limits, or privilege boundaries are unsafe. Observe-only
is the default; `DryRunQuarantine` records what would happen, and `Quarantine`
requires explicit configuration and an external vault while supporting hash and
path allowlists and enforcing a bounded action rate.

The lifecycle scripts publish, validate, install, inspect, and remove the
service. Installation uses the managed virtual account `NT SERVICE\UtoAegis`,
grants read/execute access to the monitored tree, and adds only `Delete child`
when quarantine mode is explicitly enabled. Service health, recovery scans,
detections, decisions, and operational failures are written to the Windows
Application event log.

See the [Windows service deployment guide](docs/windows-service.md) for the
configuration schema, protected directory layout, staged rollout, commands,
recovery workflow, and current limitations.

## Quarantine and recovery

Quarantine is an explicit command and requires at least one configured detector.
The file is scanned first and is not moved unless that complete scan reports a
hash-reputation or signature match:

```powershell
Copy-Item samples/harmless-test-file.txt harmless-quarantine-test.txt

dotnet run --project src/UtoAegis.Cli -- quarantine add `
  --vault data/quarantine `
  --signatures samples/signatures.example.jsonl `
  --history data/history.db `
  harmless-quarantine-test.txt
```

The demonstration rule deliberately matches harmless text. Do not test this
workflow with real malware.

The vault reopens the detected file through a Windows handle, prevents new
write or delete sharing, recomputes SHA-256 and length through that exact handle,
flushes the payload and recovery metadata, and only then marks the same handle
for deletion. If identity changed after scanning, the source is preserved and
quarantine fails.

Inspect and restore entries with their canonical quarantine ID:

```powershell
dotnet run --project src/UtoAegis.Cli -- quarantine list `
  --vault data/quarantine --limit 25

dotnet run --project src/UtoAegis.Cli -- quarantine show `
  --vault data/quarantine <quarantine-id>

dotnet run --project src/UtoAegis.Cli -- quarantine restore `
  --vault data/quarantine `
  --destination restored-quarantine-test.txt `
  <quarantine-id>
```

Restore verifies the retained payload's SHA-256 and length, rejects reparse-point
destination paths, and never overwrites a file or directory. The payload remains
in the vault after restore for recovery evidence; there is no purge command yet.

On Windows, vault ACL inheritance is disabled. Access is limited to the current
user, Local System, and administrators, and the current user receives an
explicit execute deny on inherited files. Payloads also use the hidden,
read-only `.uaq` extension. The vault is not encrypted or tamper-evident, so its
directory still requires normal host and backup protections.

## Detection history and structured logs

History is disabled unless `--history` is supplied. Keep its SQLite database
separate from the reputation database:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan `
  --history data/history.db README.md

dotnet run --project src/UtoAegis.Cli -- scan-directory `
  --recursive --history data/history.db samples
```

Each stored scan has a correlation ID and includes its target, timestamps,
outcome, per-file hashes and detection signals, signature matches, failures,
and traversal issues. Recent summaries and full records can be queried in human
or JSON form:

```powershell
dotnet run --project src/UtoAegis.Cli -- history list `
  --history data/history.db --limit 25

dotnet run --project src/UtoAegis.Cli -- history show `
  --history data/history.db <scan-id>
```

Retention is an explicit operator action. This deletes complete scan records
and their related file, match, and issue rows in one cascading operation:

```powershell
dotnet run --project src/UtoAegis.Cli -- history prune `
  --history data/history.db --older-than-days 30
```

Operational JSON Lines logs are written to standard error and share the same
scan ID. `--quiet` suppresses those logs but does not disable requested history
storage or hide errors. History databases and SQLite sidecars inside a scanned
directory are excluded and reported rather than scanned as ordinary files.

## Indicator format

Imports use one JSON object per line:

```json
{"sha256":"64 lowercase or uppercase hexadecimal characters","classification":"Malware","source":"feed-name","malwareFamily":"Optional.Family","firstSeenUtc":"2026-10-02T00:00:00Z"}
```

Required fields:

- `sha256`: exactly 64 hexadecimal characters; stored lowercase.
- `source`: 1–200 printable characters.

Optional fields:

- `classification`: currently only `Malware`; omitted values default to it.
- `malwareFamily`: up to 200 printable characters.
- `firstSeenUtc`: an ISO 8601 timestamp.

The reader rejects unknown or duplicate JSON properties, malformed hashes,
control characters, conflicting duplicate indicators, lines over 16 KiB, files
over 128 MiB, and imports over 250,000 unique indicators. The full input is
validated before the database transaction starts.

## Signature format

Signature rules also use one JSON object per line:

```json
{"id":"demo.marker","name":"Harmless test marker","source":"local-demo","hexPattern":"55746f4165676973"}
```

- `id`: 1–128 ASCII letters, digits, dots, underscores, or hyphens; starts with
  a letter or digit and is unique without regard to case.
- `name` and `source`: 1–200 printable characters.
- `hexPattern`: 8–1024 exact bytes encoded as hexadecimal without separators.

The reader rejects malformed UTF-8, comments, trailing commas, unknown or
duplicate properties, conflicting rule IDs, lines over 8 KiB, files over 16
MiB, and more than 1,024 unique rules. Identical duplicate rules are counted
and ignored.

`fixed-byte-v1` is deliberately narrow: matching is case-sensitive and
contiguous, with no wildcards, regular expressions, or boolean conditions. A
`NoMatch` result means only that none of the configured rules matched; it is not
a clean-file verdict.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Operation succeeded; a reputation lookup may be `Unknown`. |
| `2` | Invalid command-line usage. |
| `3` | The file could not be hashed. |
| `4` | Hashing succeeded but reputation lookup failed. |
| `5` | Indicator import or database initialization failed. |
| `6` | Signature rules could not load or signature scanning failed. |
| `7` | Directory traversal could not start or exceeded a safety limit. |
| `8` | Directory scan completed partially without a detection. |
| `9` | Requested history initialization, storage, or management failed. |
| `10` | A malicious-hash or signature match was detected in a complete scan. |
| `11` | A detection occurred, but the directory scan was partial. |
| `12` | A detection occurred, but its requested history record could not be stored. |
| `13` | Real-time monitoring could not start or failed because of a filesystem operation. |
| `14` | A detected file was successfully quarantined. |
| `15` | Quarantine storage or management failed. |
| `16` | Restore failed or was refused to avoid an overwrite or integrity violation. |
| `130` | Operation was cancelled. |

## Security review

- Scanned files are opened read-only, streamed, and never interpreted or
  executed. Size and last-write metadata are checked within each scan and
  across the combined hash/signature workflow.
- Signature patterns and rule collections have explicit size limits. Rented
  scan buffers are cleared before returning to the shared pool.
- A rule match is evidence, not proof of maliciousness. Rule provenance,
  quality review, and false-positive testing remain operational requirements.
- Imports use parameterized SQL and one transaction. A failed record rolls back
  the complete batch rather than leaving partial threat data.
- The SQLite schema is versioned with `PRAGMA user_version`, uses strict typing,
  and indexes SHA-256 as its primary key.
- The database is integrity-sensitive. This milestone does not sign indicator
  feeds or the database, so only trusted operators should be able to replace or
  modify them.
- Every quarantine action revalidates the expected hash and length through the
  exact Windows handle used for removal. Path and metadata checks alone are not
  treated as authorization to change a file.
- Directory scans reject a reparse-point root, never follow discovered reparse
  points, and revalidate entries immediately before scanning. These controls
  reduce traversal and replacement races but cannot eliminate filesystem
  time-of-check/time-of-use risk.
- Directory discovery and retained results use memory proportional to the
  bounded file count. The scanner refuses to scan a partial discovery set when
  a hard file or directory limit is exceeded.
- Scan history uses its own identified, versioned SQLite schema with strict
  tables, foreign keys, parameterized writes, and one transaction per record.
  Duplicate scan IDs are rejected instead of replacing audit data.
- History is opt-in because it stores sensitive paths, hashes, rule metadata,
  and failure details. The database is neither encrypted nor tamper-evident;
  operators must restrict file access, back it up appropriately, and apply a
  retention policy with `history prune`.
- Paths in logs can disclose usernames or directory structures. Production log
  storage needs access controls and a retention policy.
- Real-time monitoring starts the watcher before its initial scan, debounces
  bursts, bounds its managed queue, and converts watcher or queue overflow into
  an explicit recovery scan. Filesystems can still coalesce, reorder, or delay
  notifications, so the watcher is a best-effort signal rather than an audit
  log or transactional snapshot.
- Changed entries are revalidated as regular files inside the monitored root
  immediately before scanning. Reparse points are not followed, but replacement
  races remain possible after validation.
- CLI detection remains observational unless the operator invokes `quarantine
  add`. The Windows service is observe-only by default; automatic quarantine
  requires an administrator-controlled policy and installation layout. Hash and
  path allowlists are evaluated before dry-run or quarantine behavior, and a
  sliding-window rate limit bounds attempted actions.
- The service uses a passwordless `NT SERVICE\UtoAegis` virtual account. Its
  executable and policy inputs are read-only, writable state stays outside the
  monitored tree, and quarantine mode receives delete-child rather than general
  write access to that tree. An administrator or compromised service process
  remains inside the host trust boundary.
- Quarantine requires a completed detection and rechecks the expected SHA-256
  and length through the exact Windows file handle used for removal. This closes
  the path replacement window between validation and deletion on Windows.
- Vault payloads inherit a current-user execute deny and restricted ACL. Local
  administrators and Local System retain recovery access. Non-Windows builds do
  not provide the same handle-deletion or Windows ACL guarantees.
- Restore verifies payload integrity, refuses overwrite, rejects reparse-point
  destination segments, and records a pending state so a completed copy can be
  reconciled after interruption.
- Vault metadata is structured and atomically replaced but is not signed. ACLs
  reduce accidental or unprivileged modification; they do not make the vault
  trustworthy after administrator compromise.
- A repeated hash import updates its stored source metadata. Source trust and
  multi-source consensus are intentionally deferred until threat-intelligence
  integration.

## Milestone status

### Milestone 1 — File hash scanner

- [x] Correct SHA-256 hashing for known and empty files.
- [x] Streaming file access, cancellation, explicit failures, and structured logs.
- [x] Automated correctness and failure-path tests.

### Milestone 2 — Malware hash database

- [x] Versioned SQLite schema behind `IHashReputationStore`.
- [x] Transactional, parameterized, idempotent indicator imports.
- [x] Strict validation for hashes and untrusted JSON Lines input.
- [x] Explicit `Malicious`, `Unknown`, and `LookupFailed` outcomes.
- [x] Source, classification, family, first-seen, and update metadata.
- [x] Corruption, rollback, schema-version, and duplicate-input tests.
- [x] CLI import and reputation-aware scanning workflows.
- [x] Performance smoke test with 10,001 synthetic indicators.

### Platform foundation

- [x] Upgraded all projects to .NET 10 LTS.
- [x] Centralized package versions and committed dependency lock files.
- [x] Enabled auditing for direct and transitive NuGet dependencies.
- [x] Added GitHub Actions build and test validation.
- [x] Added weekly Dependabot checks for NuGet and GitHub Actions.

### Milestone 3 — Signature scanner

- [x] Added a stable `ISignatureScanner` boundary and explicit result statuses.
- [x] Added a bounded, streaming fixed-byte engine with boundary-safe matching.
- [x] Added a strict JSON Lines rule loader and harmless example rule.
- [x] Integrated optional signature scanning into human and JSON CLI output.
- [x] Added detection, no-match, failure, cancellation, mutation, and parser tests.
- [x] Added a 16 MiB / 32-rule performance smoke test.

### Milestone 4 — Directory scanner

- [x] Added a reusable composite per-file detection pipeline.
- [x] Added nonrecursive scanning with explicit opt-in recursion.
- [x] Bounded traversal depth, file count, directory count, and concurrency.
- [x] Rejected or skipped reparse points and revalidated files before scanning.
- [x] Preserved deterministic per-file results, traversal issues, and summaries.
- [x] Added human and JSON CLI output with distinct partial-result exit codes.
- [x] Added race, failure, limit, cancellation, and 1,000-file smoke tests.

### Milestone 5 — Detection history and structured logging

- [x] Added storage-neutral history contracts and explicit scan outcomes.
- [x] Added an identified, versioned SQLite history schema separate from reputation data.
- [x] Stored scans, file results, signature matches, and traversal issues atomically.
- [x] Added opt-in capture plus list, show, and age-based prune commands.
- [x] Correlated JSON Lines events and stored records with one scan ID.
- [x] Added explicit history-failure exit codes without losing detection signals.
- [x] Added rollback, identity, consistency, retention, and 2,000-file smoke tests.

### Milestone 6 — Real-time file monitoring

- [x] Added an event-source boundary and Windows filesystem watcher adapter.
- [x] Started watching before the initial recovery scan to reduce startup gaps.
- [x] Added per-path debounce and bounded, configurable event buffering.
- [x] Converted operating-system and managed-queue overflow into visible recovery scans.
- [x] Revalidated paths, rejected reparse points, and excluded scanner data files.
- [x] Added human and JSON Lines output, correlated logs, and opt-in history capture.
- [x] Added event, overflow, exclusion, cancellation, CLI, and live watcher tests.

### Milestone 7 — Safe quarantine and recovery

- [x] Added storage-neutral quarantine, entry, result, and restoration contracts.
- [x] Required completed detector evidence, expected SHA-256, and expected length.
- [x] Revalidated and removed the exact opened Windows file handle.
- [x] Added a restricted vault with inherited execute denial and `.uaq` payloads.
- [x] Flushed payload and atomic metadata before removing the source.
- [x] Verified payload integrity and refused destination overwrite during restore.
- [x] Added pending-restore reconciliation for interruption recovery.
- [x] Added add, list, show, and restore CLI workflows with JSON and exit codes.
- [x] Added ACL, corruption, identity-race, overwrite, recovery, and live CLI tests.

### Milestone 8 — Supervised Windows monitoring service

- [x] Added an independently tested response-policy boundary.
- [x] Kept service response observe-only by default and added dry-run behavior.
- [x] Added hash and path-prefix allowlists plus a bounded action rate.
- [x] Added a .NET 10 Windows Service host with startup configuration validation.
- [x] Added health, recovery, detection, decision, and failure Event Log events.
- [x] Added a virtual service account and mode-specific least-privilege ACLs.
- [x] Isolated trusted signature policy from service-writable operational state.
- [x] Added publish, install, status, and recoverable removal scripts.

The next milestone should add authenticated threat-intelligence updates. Feeds
and signature policy need cryptographic signatures, rollback protection,
staged validation, atomic activation, and a last-known-good recovery path before
UtoAegis can safely update detection content without manual replacement.
