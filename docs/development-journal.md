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
