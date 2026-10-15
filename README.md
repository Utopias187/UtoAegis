# UtoAegis

UtoAegis is an incrementally developed Windows endpoint-security product. It
currently combines safe SHA-256 hashing, a versioned local reputation database,
streaming exact-byte signature detection, and bounded directory traversal. It
does not execute scanned files.

Implementation decisions and verification notes are recorded in the
[development journal](docs/development-journal.md).

## Current architecture

- `UtoAegis.Core` contains file and directory scanner contracts, result models,
  validation, and hash, reputation, and signature engines. It has no SQLite
  dependency.
- `UtoAegis.Infrastructure` contains the SQLite reputation store and strict
  JSON Lines readers for indicators and signature rules.
- `UtoAegis.Cli` handles commands, cancellation, structured logs, output, and
  process exit codes.

```text
directory -> bounded traversal -> regular file paths -|
single file ------------------------------------------|-> composite file scanner
                                                       |-> SHA-256 -> reputation
                                                       |-> fixed-byte signatures
                                                       |-> one explicit file result
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
| `10` | A malicious-hash or signature match was detected in a complete scan. |
| `11` | A detection occurred, but the directory scan was partial. |
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
- A later enforcement or quarantine action must revalidate file identity at the
  point of action; path and metadata checks cannot eliminate every race.
- Directory scans reject a reparse-point root, never follow discovered reparse
  points, and revalidate entries immediately before scanning. These controls
  reduce traversal and replacement races but cannot eliminate filesystem
  time-of-check/time-of-use risk.
- Directory discovery and retained results use memory proportional to the
  bounded file count. The scanner refuses to scan a partial discovery set when
  a hard file or directory limit is exceeded.
- Paths in logs can disclose usernames or directory structures. Production log
  storage needs access controls and a retention policy.
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

The next milestone is detection history and structured logging. It should store
scan-level and per-file outcomes behind an independent interface, define
retention and privacy behavior, and keep security data separate from
operational history.
