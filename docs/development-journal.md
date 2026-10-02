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
