# UtoAegis Development Journal

This journal records engineering decisions, verification results, and known
limitations for each completed milestone. It is not a replacement for API
documentation or issue tracking.

## 2026-10-02 — Milestone 1: SHA-256 file scanner

### Goal

Create the smallest useful scanning foundation: accept one file path, calculate
its SHA-256 digest without executing or modifying the file, and return a result
that future detection components can consume.

### Decisions

- Use C# for the initial Windows product because the available .NET platform
  provides maintained cryptography and file APIs and leaves a direct path to a
  Windows service or desktop UI.
- Keep scanning logic in `UtoAegis.Core`. The CLI is an adapter and contains no
  hashing logic.
- Expose the scanner through `IFileHashScanner` so later orchestration code does
  not depend on one implementation.
- Stream files asynchronously instead of loading them into memory. The default
  stream buffer is 1 MiB.
- Return explicit statuses for expected file-access failures. Cancellation
  remains an exception because callers commonly compose it through cancellation
  tokens.
- Write scan results to standard output and operational logs to standard error,
  allowing scripts to consume output without discarding diagnostics.
- Do not assign a security verdict. A digest is an identifier; an unknown digest
  is not evidence that a file is safe.

### Security notes

The scanner opens files read-only and requests sequential access. It prevents
new write handles while its read handle is open, then compares size and
last-write metadata before accepting the digest. This detects common mutation
cases but does not eliminate every time-of-check/time-of-use race. Any future
quarantine action must revalidate file identity immediately before acting.

Paths appear in operational logs and may disclose usernames or directory names.
Production log storage will need access controls and a retention policy.

### Verification

- Release build completed with zero warnings.
- Eight automated tests passed, covering known content, an empty file, missing
  files, directories, invalid paths, sharing violations, cancellation, and
  invalid scanner configuration.
- Human-readable and JSON CLI output were exercised successfully.
- Missing-file behavior returned the documented process exit code `3`.
- A synthetic 64 MiB file was streamed in approximately 303 ms on the initial
  development machine (about 211 MiB/s). This is a smoke benchmark, not a
  production performance guarantee.

### Known limitations

- There is no malicious-hash database or verdict engine yet.
- There is no recursive scanning, persistent history, or quarantine.
- Mutation detection is metadata-based and intentionally best effort.
- The project currently targets .NET 8 to match the installed toolchain. It must
  move to a supported long-term release before production distribution.

### Next milestone

Add a versioned local malware-hash database behind an
`IHashReputationStore` interface. Imports must validate SHA-256 values and use a
transaction; lookups must distinguish malicious, unknown, and lookup failure.

## 2026-10-02 — Milestone 2: malware hash database

### Goal

Turn the SHA-256 digest into a useful detection signal by comparing it with a
local, versioned database of malicious indicators. Preserve the distinction
between an absent indicator and a trustworthy clean verdict.

### Decisions

- Keep `IHashReputationStore`, indicator validation, and result types in the
  dependency-free core project. SQLite remains an infrastructure detail.
- Use Microsoft.Data.Sqlite with a strict version-one schema. SHA-256 is the
  primary key, making exact lookup indexed without another index.
- Represent lookup outcomes as `Malicious`, `Unknown`, or `LookupFailed`.
  Operational failure is never collapsed into an unknown result.
- Validate a complete JSON Lines feed before opening the write transaction.
  Conflicting duplicate hashes reject the file; identical duplicates are
  counted and ignored.
- Use parameterized upserts inside one transaction. A repeated identical import
  is idempotent and does not rewrite its update timestamp.
- Limit import size, line length, nesting depth, indicator count, text length,
  and accepted JSON properties to bound resource usage and reduce ambiguity.
- Return exit code `10` for a detection so automation can distinguish a threat
  signal from scanner or database failure.

### Verification

- Release builds complete with zero warnings.
- Twenty-three automated tests pass across the core and infrastructure suites.
- Tests cover normalization, validation, missing and matched hashes, idempotent
  imports, unsupported schema versions, malformed JSON, conflicting duplicates,
  duplicate JSON properties, database corruption, and transaction rollback.
- End-to-end CLI verification imported the harmless sample, returned
  `Malicious` with exit code `10` for the matching file, and returned `Unknown`
  with exit code `0` for an absent digest.
- A 10,001-indicator synthetic feed imported in approximately 2.35 seconds on
  the development machine after preparing the upsert command once. This is a
  smoke benchmark rather than a performance guarantee.

### Security notes

The database materially influences detection results and is therefore trusted
security data. SQLite integrity checks and schema constraints protect against
accidental invalid data, not a local attacker who can replace the database.
Signed feeds, authenticated updates, and locked-down file permissions are
required before remote threat-intelligence updates are accepted.

The current schema stores one source record per digest. A later import can
replace that metadata. Multi-source observations, trust ranking, revocation,
and feed provenance should be added with threat-intelligence integration rather
than improvised inside the scanner.

### Known limitations

- Only exact SHA-256 matches are supported; there are no byte-pattern rules.
- Indicators and databases are not cryptographically signed.
- The store does not yet model indicator expiry, revocation, or several sources
  reporting the same digest.
- The project still targets .NET 8 to match the installed toolchain and must
  move to a supported long-term release before production distribution.

### Next milestone

Add signature-based scanning behind its own interface. Start with a constrained
rule model and harmless byte-pattern fixtures, measure streaming performance,
and evaluate YARA only after the integration boundary and safety behavior are
proven.

## 2026-10-02 — Platform hardening before Milestone 3

### Goal

Move off the near-end-of-support .NET 8 baseline and make dependency and build
verification reproducible before signature-scanning work begins.

### Decisions

- Target .NET 10 across the solution from `Directory.Build.props` rather than
  repeating the target framework in every project.
- Add `global.json` with a .NET 10 minimum and latest-feature roll-forward so
  supported .NET 10 feature bands can build the repository.
- Upgrade Microsoft.Data.Sqlite to 10.0.12 while retaining MSTest 4.4.1, which
  already supports .NET 10.
- Manage direct package versions in `Directory.Packages.props` and commit a lock
  file for every project.
- Audit direct and transitive dependencies during restore, treating NuGet
  vulnerability advisories NU1901 through NU1904 as build errors.
- Run locked restore, release build, tests, and a vulnerability report in GitHub
  Actions. Pin third-party workflow actions to full commit hashes.
- Schedule weekly Dependabot checks for both NuGet packages and workflow actions.

### Verification

- The repository selected .NET SDK 10.0.401 through `global.json`.
- Locked restore completed for all five projects.
- Release build completed with zero warnings and zero errors.
- All 23 automated tests passed on `net10.0`.
- NuGet reported no known vulnerable direct or transitive packages.

### Milestone 3 readiness

The platform upgrade does not change scanner behavior or database schema.
Milestone 3 can add signature scanning behind a new independent interface while
the existing hash and reputation contracts remain stable.

## 2026-10-15 — Milestone 3: signature-based scanner

### Goal

Add a second local detection layer that can identify known byte sequences
without executing or loading an entire scanned file into memory. Keep the
engine replaceable so richer rule technology can be evaluated independently.

### Design and data flow

- `ByteSignatureRule` validates and normalizes bounded rule metadata and exact
  hexadecimal patterns.
- `ISignatureScanner` separates orchestration from the first implementation.
- `FixedByteSignatureScanner` reads a file in 1 MiB chunks and retains only the
  overlap needed to find a pattern crossing a chunk boundary.
- `JsonLinesSignatureRuleReader` treats rule files as untrusted input and fully
  validates them before constructing a scanner.
- The CLI optionally runs hash reputation and signature detection together,
  reports each signal independently, and returns detection exit code `10` if
  either engine matches.

```text
rules.jsonl -> strict reader -> validated rules --|
                                                  |-> fixed-byte scanner -> matches
file path ----------------------------------------|
```

The scanner reports the first offset for every matching rule. It continues to
the end of the file so read errors and file changes cannot be hidden by an
early match. `Detected`, `NoMatch`, and operational failures are distinct.

### Security review

- Files are opened read-only with sequential access and are never executed.
- Rule count, pattern length, line length, nesting depth, and rule-file size are
  bounded to limit memory and CPU abuse.
- Shared byte buffers are cleared before being returned to `ArrayPool`.
- Size and last-write metadata are checked during each read. The CLI also takes
  a metadata snapshot around the combined workflow so hash and signature
  results are discarded if a common mutation is observed between stages.
- Metadata checks remain best effort. A privileged attacker may preserve or
  restore metadata, so future quarantine must reopen and revalidate the target.
- Exact byte signatures can produce false positives. Matches retain rule ID,
  name, source, byte offset, and pattern length so decisions remain auditable.
- Rule files affect verdicts and are trusted security data. Production updates
  will require authentication, signing, rollback protection, and source policy.

### YARA-X evaluation

[YARA-X](https://virustotal.github.io/yara-x/docs/) supports text, hexadecimal,
and regular-expression patterns combined with boolean rule conditions and file
format modules. Its native API separates rule compilation from scanning and
supports timeouts and reusable compiled rules. Those capabilities are useful,
but native distribution, lifecycle management, rule compatibility, resource
limits, and failure isolation need a dedicated integration milestone.

The current engine therefore remains intentionally small rather than
implementing a partial YARA language. A future YARA-X adapter can implement
`ISignatureScanner` while preserving the CLI and result boundary established
here.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 63 automated tests passed: 34 core, 22 infrastructure, and 7 CLI tests.
- Tests cover validation, chunk-boundary matches, stable match ordering,
  duplicate rules, malformed JSON, file and line limits, cancellation, access
  failures, and cross-stage metadata changes.
- A 16 MiB file with 32 nonmatching rules completed within the 30-second smoke
  limit; the complete core test assembly ran in under one second on the
  development machine. This is a regression signal, not a production SLA.
- End-to-end CLI checks returned `10` for the harmless demonstration match, `0`
  for a no-match scan, and `6` for an unavailable rule file. JSON output was
  also verified.

### Known limitations

- Rules support only exact, contiguous byte patterns. There are no wildcards,
  regular expressions, conditions, namespaces, or executable-format modules.
- Matching cost grows with both file size and rule count. A production-scale
  rule corpus will require a multi-pattern algorithm or a vetted YARA-X adapter.
- Only the first match per rule is retained to bound result growth.
- Rule files are local and unsigned, with no update or revocation mechanism.
- Results are emitted to the console but are not yet stored as detection history.

### Definition of done

- [x] Stable signature scanner interface and explicit outcomes exist.
- [x] Streaming matching detects patterns inside and across read buffers.
- [x] Strict rule parsing rejects ambiguous or unbounded input.
- [x] CLI human, JSON, logging, and exit-code behavior is integrated.
- [x] Harmless positive and negative paths are verified.
- [x] Error handling, cancellation, mutation checks, and performance are tested.
- [x] Security decisions, false-positive risk, and limitations are documented.

### Next milestone

Build directory and recursive scanning on top of the existing single-file
engines. Traversal must bound concurrency, avoid directory links by default,
continue after per-file failures, and produce a deterministic summary without
calling any `NoMatch` or `Unknown` file clean.

## 2026-10-15 — Milestone 4: directory and recursive scanner

### Goal

Apply the established hash, reputation, and signature stages to a directory
without turning traversal into an unbounded or misleading operation. Preserve
an explicit outcome for each scanned file and distinguish complete, partial,
failed, and detected runs for both people and automation.

### Design and data flow

- `IFileScanner` and `CompositeFileScanner` compose the existing per-file
  stages and enforce one cross-stage metadata-consistency boundary.
- `IDirectoryScanner` and `DirectoryScanner` discover regular files before
  scanning them with bounded asynchronous concurrency.
- Nonrecursive traversal is the default; recursion requires `--recursive`.
- Default limits are 100,000 files, 50,000 directories, depth 64, and four
  concurrent scans. The corresponding absolute maxima are 1,000,000, 250,000,
  256, and 32.
- A hard discovery-limit failure prevents scanning an incomplete file set.
- Files and issues are sorted with ordinal path ordering so output does not
  depend on filesystem enumeration or task completion order.
- Configured rule and database files are excluded from directory scans. SQLite
  sidecar files are also excluded. Exclusions remain visible as issues and make
  the result partial.

```text
root -> bounded discovery -> sorted regular files -> bounded workers
                                                  -> composite file scanner
                                                  -> per-file results + summary
```

The CLI exposes `scan-directory`, `--recursive`, and `--max-concurrency` while
reusing `--database`, `--signatures`, `--json`, and `--quiet`. Exit code `7`
means the directory scan failed, `8` means partial without a detection, `10`
means detection in a complete scan, and `11` means detection with partial
coverage.

### Security review

- A reparse-point root is rejected and discovered file or directory reparse
  points are skipped. The scanner does not intentionally leave the requested
  tree through junctions or symbolic links.
- Every discovered file is revalidated immediately before its scan. A file
  that disappears, becomes a directory, or becomes a reparse point is skipped
  and reported rather than silently accepted.
- Filesystem checks remain best effort. Entries can change after validation,
  and metadata checks cannot prove stable identity against a capable local
  attacker. A future enforcement action must reopen and revalidate its target.
- Traversal work, concurrency, and retained result counts are bounded. The
  current discovery-first design still uses memory proportional to the number
  of discovered files, up to the configured limit.
- Access-denied, disappeared, excluded, and I/O-affected entries make the run
  partial. The interface never describes `Unknown` or `NoMatch` as clean.
- Paths are included in results and operational logs. Retention, access
  control, and path minimization are requirements for persistent history.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 91 automated tests passed: 54 core, 22 infrastructure, and 15 CLI tests.
- Tests cover recursive and nonrecursive traversal, stable ordering, reparse
  handling, depth and item limits, invalid roots, partial results, cancellation,
  bounded concurrency, CLI parsing, and exit-code precedence.
- A race test removes a file after discovery and confirms it is skipped and
  reported during pre-scan revalidation.
- A real 1,000-file recursive SHA-256 smoke scan completed inside its 30-second
  limit; the complete core test assembly ran in approximately five seconds on
  the development machine. This is a regression signal, not a production SLA.
- End-to-end CLI checks verified complete, partial, detected, failed, human,
  and JSON result paths.

### Known limitations

- Traversal is discovery-first rather than streamed through a bounded channel.
  This simplifies deterministic limits but retains all discovered paths and
  all completed results in memory.
- Reparse-point avoidance and metadata checks do not provide a transactional
  filesystem snapshot.
- There is no ignore-pattern language, incremental scan cache, archive
  expansion, scheduled scanning, or quarantine.
- Results are returned and logged but are not persisted as detection history.

### Definition of done

- [x] Existing per-file engines are composed behind a reusable interface.
- [x] Directory and opt-in recursive discovery have explicit safety limits.
- [x] Link handling, entry changes, partial coverage, and failures are visible.
- [x] File work is parallel but bounded; final results are deterministic.
- [x] CLI human, JSON, logging, and exit-code behavior are integrated.
- [x] Race, cancellation, failure, limit, and performance paths are tested.
- [x] Security assumptions, memory behavior, and limitations are documented.

### Next milestone

Add detection history and structured logging behind an independent persistence
interface. Store scan-level and per-file outcomes, define retention and privacy
policies, and avoid mixing append-only operational history with the trusted
reputation database.

## 2026-10-15 — Milestone 5: detection history and structured logging

### Goal

Make scan outcomes auditable across CLI invocations without coupling the scan
engines to one database. Preserve enough structured evidence to explain a
detection or failure while keeping persistence optional because paths and
hashes are sensitive operational data.

### Design and data flow

- `IScanHistoryStore` defines initialization, immutable append, summary listing,
  full-record retrieval, and retention pruning independently of SQLite.
- `ScanHistoryRecord` projects file and directory results into one stable model
  containing target metadata, timing, outcome, files, signature matches, and
  traversal issues.
- `SqliteScanHistoryStore` uses a database separate from malicious reputation
  data. An application ID and schema version reject unrelated or newer files.
- One transaction inserts a scan header and all child rows. Duplicate scan IDs
  fail, and a failed child insert rolls back the complete record.
- Summary queries are capped at 200 rows. Full records validate stored counts
  against their file, detection, failure, match, and issue details.
- Foreign-key cascades make retention deletion atomic for each scan graph.
- Every scan receives a GUID used by operational JSON Lines logs, persisted
  history, JSON results, and `history show`.

```text
scan result -> history projection -> IScanHistoryStore -> SQLite transaction
     |                                                        |
     +-> correlated JSON Lines logs                           +-> list/show/prune
```

History capture is enabled with `--history <path>`. `history list` returns
recent summaries, `history show` returns one complete record, and `history
prune --older-than-days <days>` deletes records before the calculated UTC
cutoff. A missing database is rejected by management commands rather than
silently created after a path typo.

### Failure and exit-code behavior

- History initialization failure prevents a requested history-enabled scan
  from starting and returns exit code `9`.
- A post-scan write failure returns `9` when there was no detection and `12`
  when there was a detection. Code `12` preserves both facts: security evidence
  was found, and the requested audit record was not stored.
- Operational logs use standard error, result output uses standard output, and
  `--quiet` suppresses logs without suppressing storage failures.
- A history database and its `-wal` and `-shm` sidecars are excluded when they
  fall inside a directory target. The exclusions remain visible as partial
  coverage rather than being silently omitted.

### Security and privacy review

- History contains paths, SHA-256 values, timestamps, malware-family and source
  metadata, signature rule details, offsets, and errors. It is opt-in and needs
  directory permissions, backup controls, and a retention policy appropriate
  for the machine and organization.
- The database is structured and transactionally consistent but is not
  encrypted, signed, or tamper-evident. It must not be treated as trustworthy
  forensic evidence after a local attacker gains write access.
- History is operational data and is not joined into the trusted reputation
  database. Compromise or pruning of history therefore does not change scan
  verdicts.
- Parameterized writes prevent scan-controlled values from becoming SQL. Strict
  tables, foreign keys, application identity, schema versioning, and count
  validation catch common corruption or wrong-database mistakes.
- Retention is explicit instead of automatic. This avoids surprising data loss,
  but deployment policy must schedule pruning and monitor database growth.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 113 automated tests passed: 57 core, 34 infrastructure, and 22 CLI tests.
- Tests cover projection, schema identity, rich-result round trips, immutable
  IDs, transactional rollback, newest-first limits, missing records, retention
  cascades, internal count validation, parser rules, and exit-code precedence.
- A 2,000-file append-and-read smoke test completed inside its 30-second limit;
  the complete infrastructure test assembly ran in approximately three seconds
  on the development machine. This is a regression signal, not a production
  service-level guarantee.
- End-to-end CLI verification captured a real scan, listed it, retrieved the
  same record by scan ID, and exercised retention without deleting the new row.

### Known limitations

- History is local and SQLite-backed; there is no remote collector, forwarding,
  export command, dashboard, or multi-host identity.
- Full-record retrieval materializes every stored file and match in memory.
- Retention is manual and does not compact the SQLite file automatically.
- There are no tamper-evident hashes, signatures, encryption-at-rest controls,
  or operating-system event-log integration.
- Scans are still initiated manually; filesystem changes are not monitored.

### Definition of done

- [x] Storage-neutral contracts preserve scan, file, match, and issue details.
- [x] History data uses an independent, identified, versioned database.
- [x] Complete records are appended atomically and duplicate IDs are rejected.
- [x] Operators can list, inspect, and prune history through the CLI.
- [x] Logs, output, and stored records share one scan correlation ID.
- [x] Privacy, retention, failure precedence, and integrity limits are explicit.
- [x] Rollback, corruption, retention, CLI, and performance paths are tested.

### Next milestone

Add real-time file monitoring behind an independent event-source interface.
Filesystem events should enter a bounded, debounced queue, watcher overflow
must trigger a visible recovery scan, and the monitor should reuse the current
scanner and history contracts. Quarantine and automatic deletion remain out of
scope until identity revalidation and recovery semantics are designed.

## 2026-10-15 — Milestone 6: real-time file monitoring

### Goal

Continuously apply the existing detection pipeline to filesystem changes while
making dropped events, partial coverage, and operational failures visible. Keep
monitoring observational until quarantine identity and recovery guarantees are
designed and tested.

### Design and data flow

- `IFileMonitorEventSource` keeps the orchestration independent of one watcher
  implementation and makes event streams deterministic in tests.
- `FileSystemWatcherEventSource` begins watching during construction, before
  the initial directory recovery scan starts. It publishes created, changed,
  and renamed paths through a bounded channel.
- `FileMonitoringEngine` performs an initial recovery scan, debounces event
  bursts by normalized path, revalidates each changed entry, and invokes the
  existing composite file scanner.
- The default debounce interval is 500 milliseconds. It can be configured from
  zero to 60 seconds with `--debounce-ms`.
- The managed queue defaults to 4,096 events and can be configured from 1 to
  65,536 with `--queue-capacity`. The operating-system watcher buffer defaults
  to 16 KiB and is capped at 64 KiB.
- Overflow from either buffer becomes an explicit event. Pending per-file work
  is cleared and a full recovery scan runs instead of claiming complete event
  coverage.
- Rule, reputation, and history files and SQLite sidecars are excluded by both
  the watcher adapter and scan validation. This prevents monitor-generated
  history writes from feeding back into the scanner.
- Every changed-file or recovery result receives its own scan ID for optional
  history storage. A separate session ID correlates the long-running monitor's
  operational logs and JSON Lines output.

```text
filesystem notifications -> bounded queue -> per-path debounce -> validate
           | overflow ------------------------------------------> recovery scan
                                                               -> file scanner
                                                               -> output/history
```

### Failure and output behavior

- Ctrl+C cancels the event wait and returns exit code `130`.
- Files that disappear before their debounce period ends are reported as
  unavailable rather than scanned or silently ignored.
- Paths outside the root, reparse points, directories, excluded files, source
  failures, and overflow are represented as typed monitor issues.
- Human output summarizes each recovery and changed-file scan. `--json`
  produces a JSON Lines stream because a monitor has many results and no single
  terminal result document.
- Operational JSON Lines logs stay on standard error. `--quiet` suppresses
  those logs, but not result output or errors.
- A requested history write failure is recorded and monitoring continues. If
  the source ends normally, the process preserves the existing history-failure
  and detection exit-code precedence. User cancellation returns `130`.
- Monitor setup or filesystem failures return exit code `13`.

### Security review

- Filesystem notifications are hints, not a complete or ordered audit stream.
  The operating system may coalesce or delay events. Explicit overflow recovery
  closes known event-loss gaps, but cannot create a transactional snapshot.
- Starting the watcher before the initial scan reduces the startup race. Events
  raised during that scan remain queued and are processed afterward.
- Event paths are normalized and checked to remain under the configured root.
  The root, parent segments, and target are checked for reparse points before a
  scan. Files can still change after validation, so enforcement must revalidate
  identity through an opened handle immediately before quarantine.
- Queue, debounce, directory traversal, and recovery-scan concurrency are
  bounded. Changed-file scans are processed sequentially while the watcher
  continues buffering events.
- State files are excluded exactly, including SQLite `-wal` and `-shm`
  sidecars. Placing a history database outside the watched root is still
  recommended because exclusions intentionally make recovery scans partial.
- Monitoring never executes, modifies, quarantines, or deletes a target.

### Verification

- Release build completed on .NET 10 with zero warnings and zero errors.
- All 132 automated tests passed: 64 core, 40 infrastructure, and 28 CLI tests.
- Engine tests cover initial recovery, same-path debounce, overflow recovery,
  source errors, paths outside the root, unavailable and excluded entries, and
  cancellation while idle.
- Infrastructure tests use the real Windows watcher for created-file delivery,
  excluded-file suppression, disposal, and bounded-queue overflow behavior.
- CLI tests cover monitor parsing, bounded option ranges, command-specific
  validation, and the dedicated failure exit code.
- A release-build smoke test started the real CLI monitor against an isolated
  temporary directory, observed the initial recovery result, created a file,
  and received completed changed-file scan events.

### Known limitations

- `FileSystemWatcher` does not guarantee one event per write, stable ordering,
  or delivery when the host or process is unavailable. A single write can emit
  more than one scan if related events arrive outside the debounce window.
- Changed-file scans are sequential. Sustained write rates beyond scan
  throughput can fill the queue and trigger repeated recovery scans.
- The monitor has no durable event journal or resume cursor across restarts.
- Cancellation takes precedence over accumulated detection or history-failure
  exit state because it is an explicit operator stop.
- There is no quarantine, remediation, notification service, background Windows
  service, or desktop interface yet.

### Definition of done

- [x] Monitoring depends on a replaceable event-source interface.
- [x] Startup includes an initial recovery scan while new events are captured.
- [x] Event bursts and memory use are bounded with configurable limits.
- [x] Known event loss produces a visible issue and full recovery scan.
- [x] Existing detection, history, human output, JSON output, and logs are reused.
- [x] Root containment, reparse handling, state-file exclusions, and cancellation are tested.
- [x] Live watcher behavior, failure semantics, and limitations are documented.

### Next milestone

Design safe quarantine and recovery. Quarantine must revalidate identity at the
point of action, move content into a restricted non-executable store, retain
tamper-resistant metadata for restoration, prevent path traversal and overwrite
on recovery, and remain opt-in until rollback behavior is proven.

## 2026-10-16 — Milestone 7: safe quarantine and recovery

### Goal

Add an explicit, reversible response to confirmed local detections without
turning monitoring into automatic deletion. Revalidate the file at the moment
of action, isolate it in a restricted non-executable vault, and make restoration
integrity and overwrite behavior predictable.

### Design and data flow

- `IQuarantineStore` separates response orchestration from the filesystem vault.
- `QuarantineRequest` requires a normalized expected SHA-256, expected length,
  and at least one bounded detection-evidence value.
- `quarantine add` performs the existing complete composite scan first. It
  refuses to act without `--database`, `--signatures`, or both, and it does not
  quarantine an unknown or no-match result.
- On Windows, the vault opens the source with read and delete access while
  denying new write and delete sharing. SHA-256 and length are recomputed from
  that exact handle and compared with the completed scan result.
- The verified handle is rewound and copied into a unique vault entry. The
  payload is flushed to disk, named `payload.uaq`, marked hidden and read-only,
  and accompanied by atomically replaced JSON recovery metadata.
- Only after payload and metadata succeed is the opened source handle marked
  for deletion. A failure before that point preserves the original.
- Vault ACL inheritance is disabled on Windows. The current user, Local System,
  and administrators receive recovery access, while inherited files explicitly
  deny execution to the current user.
- Restore recomputes the payload hash and length, requires an existing ordinary
  destination directory, rejects reparse-point path segments, copies through a
  flushed temporary file, and uses a non-overwriting final move.
- Metadata enters `RestorePending` before the final move. If the process stops
  after the move, a later restore verifies the destination and finalizes the
  `Restored` state rather than overwriting it.

```text
detected scan -> expected identity -> reopen exact handle -> re-hash
                                                       -> flush .uaq payload
                                                       -> atomic metadata
                                                       -> delete opened handle

active entry -> verify payload -> pending metadata -> no-overwrite move
                                                -> restored metadata
```

### CLI and exit behavior

- `quarantine add --vault <path>` scans and conditionally isolates one file.
- `quarantine list` returns newest entries first with a maximum of 200 results.
- `quarantine show` displays identity, evidence, timestamps, and restore state.
- `quarantine restore` uses the original path by default or an explicit
  `--destination`; both must be absent before a new restore begins.
- Human and JSON output are supported. Scan, quarantine, and restore operations
  produce correlated structured logs unless `--quiet` is supplied.
- Exit code `14` means a detection was successfully quarantined. Code `15`
  represents quarantine or vault-management failure. Code `16` means restore
  failed or was safely refused. An already-restored entry is idempotent success.
- Optional scan history is written before quarantine. If quarantine succeeds
  but requested history storage failed, the existing combined code `12` retains
  both the detection and audit failure signal.

### Security and recovery review

- Exact-handle hashing and deletion on Windows prevents a path swap between the
  final identity check and source removal. An already-open incompatible handle
  causes quarantine to fail rather than weakening sharing rules.
- The payload is retained after restoration. This supports evidence and repeated
  integrity checks, but consumes storage and requires a future reviewed purge
  policy.
- Restore never overwrites. A user or attacker placing any destination entry
  first causes a visible refusal. Pending-state reconciliation accepts an
  existing destination only when its complete hash and length match the payload.
- A process stop after committed quarantine metadata but before handle deletion
  can leave both the source and an active vault copy. This is a safe duplicate,
  not data loss, but there is not yet a repair command for that state.
- The JSON manifest is bounded and validated but not signed, chained, or
  encrypted. Payload hashing detects content corruption; it does not prove
  metadata provenance after a privileged attacker changes the vault.
- ACLs restrict ordinary access and deny current-user execution. Administrators
  and Local System necessarily retain control. Host compromise at that level is
  outside the vault's trust boundary.
- Non-Windows fallback behavior exists for development compatibility but cannot
  provide the same Windows handle and ACL guarantees. UtoAegis remains a Windows
  endpoint-security project.
- Quarantine remains manual. Monitor detections do not trigger removal, which
  prevents a false-positive rule from causing unattended disruption.

### Verification

- Release build completed on .NET 10 with zero warnings and zero errors.
- All 153 automated tests passed: 71 core, 47 infrastructure, and 35 CLI tests.
- NuGet reported no known vulnerable direct or transitive packages after adding
  the official filesystem access-control package.
- Contract tests cover hash, path, evidence, and state-transition validation.
- Real vault tests cover protected ACLs, inherited execute denial, exact-handle
  source removal, identity mismatch, payload corruption, overwrite refusal,
  deterministic listing, round-trip restoration, and interrupted-restore
  reconciliation.
- CLI tests cover subcommands, detector and vault requirements, option scope,
  canonical IDs, list limits, and distinct quarantine and restore exit codes.
- An end-to-end harmless-fixture test ran `add`, `list`, `show`, `restore`, and a
  second idempotent restore. It returned code `14`, removed only the copied test
  source, preserved SHA-256 after recovery, and cleaned its isolated test vault.

### Known limitations

- There is no automatic vault size limit, quota, age-based retention, or purge
  command. Listing is bounded, but payload storage must be monitored externally.
- Quarantine evidence stores bounded detector identifiers rather than a complete
  scan record. Use `--history` when the full scan result must be retained.
- Vault metadata and payloads are not encrypted or cryptographically signed.
- An interrupted quarantine can leave an orphan entry directory without metadata
  or a safe duplicate when metadata committed before source removal.
- Restore requires the destination parent directory to already exist and does
  not recreate deleted directory trees or original ACLs.
- Original last-write time is restored; creation time, alternate data streams,
  ownership, detailed ACLs, and other filesystem metadata are not preserved.
- The monitor, background service, policy engine, allowlists, and notifications
  are not connected to quarantine.

### Definition of done

- [x] Quarantine and recovery are behind a storage-neutral contract.
- [x] Only a completed configured detection can authorize quarantine through the CLI.
- [x] Source identity is rechecked through the Windows handle used for removal.
- [x] Payload and metadata are durable before the source is removed.
- [x] The Windows vault restricts access and denies current-user payload execution.
- [x] Restore verifies integrity, rejects links and overwrites, and recovers pending state.
- [x] Human, JSON, logging, history, and exit-code behavior are integrated.
- [x] Failure, corruption, interruption, ACL, and live round-trip paths are tested.

### Next milestone

Build a supervised Windows service and explicit response-policy boundary. The
service should run monitoring with least practical privilege, expose health and
detection notifications, and remain observe-only by default. Any automatic
quarantine policy must add allowlists, rate limits, dry-run behavior, and clear
operator recovery before it can be enabled.

## 2026-10-16 — Milestone 8: supervised Windows monitoring service

### Goal

Move the bounded monitor into a supervised Windows background process without
turning a detection directly into an unbounded destructive action. Keep
observe-only behavior as the default, make every active response decision
auditable, and install the service with only the filesystem rights required by
its configured mode.

### Design and data flow

- `ResponsePolicy` defines `ObserveOnly`, `DryRunQuarantine`, and `Quarantine`
  modes independently of the Windows host.
- `DetectionResponseEngine` requires a completed detection, evaluates SHA-256
  and path-prefix allowlists, and enforces a bounded sliding action window
  before invoking `IQuarantineStore`.
- `UtoAegis.Service` uses the .NET Generic Host and Windows Service lifetime to
  run the existing watcher, recovery scanner, composite detector, optional
  history store, response engine, and quarantine vault.
- Configuration is validated before the host starts. Relative operational and
  allowlist paths are anchored to the installation directory rather than the
  Service Control Manager working directory.
- Health counters and lifecycle, recovery, detection, response, monitor issue,
  and history-failure events flow through `ILogger` to the Windows Application
  event log.
- Publish, install, status, and removal scripts provide a repeatable operator
  workflow. Removal preserves files, state, vault entries, and ACLs.

```text
SCM -> service host -> watcher + recovery scans -> composite detector
                                                  -> history
                                                  -> response policy
detection -> hash allowlist -> path allowlist -> observe / dry run / rate gate
                                                        |-> quarantine vault
service state -> periodic health event + detection/decision event
```

### Response safety

- Observe-only is the constructor and configuration default. It never requires
  a vault and never changes a detected file.
- Dry-run passes through all detection and allowlist checks but does not reserve
  a rate slot or call the quarantine store.
- Quarantine mode cannot be constructed without a store, and service startup
  requires an external vault path.
- The default action limit is three attempts per five minutes. Configuration
  accepts 1–100 attempts and windows from one second through 24 hours.
- Failed attempts remain in the current window to prevent retry storms. Rate
  state is intentionally local to the running process and resets on restart.
- Path-prefix matching is boundary-aware and case-insensitive on Windows, so an
  allowlist for `safe` does not accidentally include a sibling named `safety`.
- Evidence creation moved into the core response boundary so the CLI and service
  use the same bounded detector identifiers.

### Service and privilege boundaries

- The installer uses the passwordless virtual account `NT SERVICE\UtoAegis`
  instead of Local System or an administrator account.
- Program files and the monitored tree receive read/execute access. Quarantine
  mode adds `Delete child` to the monitored tree but not general write access.
- Database, history, and vault locations receive modify access because SQLite
  sidecars and vault payloads require writes. Those locations must remain
  outside the monitored tree.
- Signature policy must remain outside service-writable state, preventing the
  service account from rewriting the byte rules that determine detections.
- Writable state cannot be a filesystem root or contain the installation
  directory. The installation directory cannot be monitored.
- Scanner data files and SQLite sidecars are excluded at both watcher and
  directory-scan boundaries to prevent self-triggering loops.
- The installer refuses a configuration already set to quarantine unless the
  administrator supplies `-AllowQuarantineResponse`.

### Verification

- Locked restore resolved Microsoft.Extensions.Hosting.WindowsServices 10.0.13
  and generated lock files for the service and its tests.
- Release builds completed on .NET 10 with zero warnings and zero errors.
- All 175 automated tests passed: 80 core, 47 infrastructure, 35 CLI, and 13
  service tests.
- Response tests cover defaults, dry-run, both allowlist types, path boundaries,
  verified evidence, rate-window expiry, incomplete scans, and missing stores.
- Service tests cover required detection sources, external state and vault
  placement, policy/state isolation, installation-directory protection,
  response settings, relative allowlist normalization, watcher limits, service
  health accounting, response dispatch, and failed-recovery history fallback.
- The validate-only startup path succeeded with environment-supplied monitor and
  database paths without starting the watcher or creating service state.
- All four PowerShell lifecycle scripts parsed successfully with the PowerShell
  abstract syntax tree parser. Registration and ACL mutations were intentionally
  not executed on the development host.
- NuGet reported no known vulnerable direct or transitive packages.

### Known limitations

- The watcher remains a best-effort user-mode signal and can coalesce, reorder,
  or lose changes. Overflow recovery narrows but does not eliminate that gap.
- This is not a kernel minifilter and does not synchronously block file access or
  execution before a scan finishes.
- Detection policy, reputation databases, and signature files are local and
  unsigned. Administrator compromise remains inside the trust boundary.
- Configuration and signatures load only at startup; there is no authenticated
  update, atomic live reload, or automatic rollback mechanism.
- The rate limit is process-local and resets on service restart.
- Application event logs are local operational notifications. Remote alerting,
  incident workflow, and notification delivery guarantees are not implemented.
- The installer grants inherited access at configured roots. A child with
  protected inheritance can remain inaccessible and will surface as a scan
  issue rather than being silently considered covered.
- Service removal preserves generated files and ACL entries for recovery. Their
  eventual retention and removal remain operator responsibilities.

### Definition of done

- [x] Response policy is independent of the host and defaults to observe-only.
- [x] Hash and path allowlists precede dry-run or active response.
- [x] Automatic quarantine attempts are bounded by a sliding time window.
- [x] The .NET 10 host runs under Windows Service Control Manager.
- [x] Configuration and unsafe path relationships fail before monitoring starts.
- [x] Health, detection, response, recovery, and failure events are visible.
- [x] The virtual service account receives mode-specific filesystem rights.
- [x] Publish, installation, inspection, removal, and recovery are documented.

### Next milestone

Add authenticated threat-intelligence updates. Detection feeds and signature
policy need cryptographic signatures, rollback protection, staged validation,
atomic activation, and last-known-good recovery before UtoAegis accepts remote
or unattended content updates.
