# UtoAegis

UtoAegis is an incrementally developed Windows endpoint-security product. It
currently provides safe SHA-256 file hashing and a versioned local reputation
database for exact malicious-hash matches. It does not execute scanned files.

Implementation decisions and verification notes are recorded in the
[development journal](docs/development-journal.md).

## Current architecture

- `UtoAegis.Core` contains file-scanning and reputation contracts, result
  models, validation, and orchestration. It has no SQLite dependency.
- `UtoAegis.Infrastructure` contains the SQLite reputation store and strict
  JSON Lines indicator reader.
- `UtoAegis.Cli` handles commands, cancellation, structured logs, output, and
  process exit codes.

```text
file path -> SHA-256 scanner -> digest -> reputation store -> explicit result
                                            |-> Malicious
                                            |-> Unknown
                                            |-> LookupFailed
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

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Operation succeeded; a reputation lookup may be `Unknown`. |
| `2` | Invalid command-line usage. |
| `3` | The file could not be hashed. |
| `4` | Hashing succeeded but reputation lookup failed. |
| `5` | Indicator import or database initialization failed. |
| `10` | A malicious-hash match was detected. |
| `130` | Operation was cancelled. |

## Security review

- Scanned files are opened read-only, streamed, and never interpreted or
  executed. Size and last-write metadata are checked for changes during hashing.
- Imports use parameterized SQL and one transaction. A failed record rolls back
  the complete batch rather than leaving partial threat data.
- The SQLite schema is versioned with `PRAGMA user_version`, uses strict typing,
  and indexes SHA-256 as its primary key.
- The database is integrity-sensitive. This milestone does not sign indicator
  feeds or the database, so only trusted operators should be able to replace or
  modify them.
- A later enforcement or quarantine action must revalidate file identity at the
  point of action; path and metadata checks cannot eliminate every race.
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

### Platform readiness for Milestone 3

- [x] Upgraded all projects to .NET 10 LTS.
- [x] Centralized package versions and committed dependency lock files.
- [x] Enabled auditing for direct and transitive NuGet dependencies.
- [x] Added GitHub Actions build and test validation.
- [x] Added weekly Dependabot checks for NuGet and GitHub Actions.

The next milestone is signature-based scanning behind a new independent scanner
interface. It should begin with a narrow, testable rule format before evaluating
full YARA integration.
