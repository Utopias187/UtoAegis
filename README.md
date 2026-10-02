# UtoAegis

UtoAegis is an incrementally developed Windows endpoint-security product. The
current milestone is a safe, reusable SHA-256 file hash scanner. It identifies
file content; it does **not** yet decide whether a hash is malicious.

Implementation decisions and verification notes are recorded in the
[development journal](docs/development-journal.md).

## Milestone 1: file hash scanner

The first milestone has two runtime components:

- `UtoAegis.Core` contains the UI-independent scanning contract and SHA-256
  implementation.
- `UtoAegis.Cli` is a thin command-line adapter that handles arguments,
  cancellation, structured logs, output, and process exit codes.

Data flows in one direction:

```text
file path -> CLI -> IFileHashScanner -> read-only stream -> SHA-256 result -> CLI
```

The scanner reads files sequentially and asynchronously, never loads the whole
file into memory, never executes it, and never modifies it. A best-effort
metadata check rejects a result if the file's size or last-write time changes
during the scan.

## Build and test

Prerequisite: the .NET 8 SDK or a newer SDK capable of targeting .NET 8.

```powershell
dotnet restore UtoAegis.slnx
dotnet build UtoAegis.slnx --no-restore
dotnet test tests/UtoAegis.Core.Tests/UtoAegis.Core.Tests.csproj --no-build
```

Scan a harmless file:

```powershell
dotnet run --project src/UtoAegis.Cli -- README.md
dotnet run --project src/UtoAegis.Cli -- --json --quiet README.md
```

The CLI writes its result to standard output and JSON Lines operational logs to
standard error. Exit code `0` means hashing succeeded, `2` means invalid CLI
usage, `3` means the file could not be scanned, and `130` means cancellation.

## Security review

- File paths and files are untrusted input. Paths are normalized and known file
  access failures become explicit statuses instead of crashes.
- The file is opened read-only with sequential-scan semantics and is never
  interpreted or executed.
- Sharing is restricted to readers while the scanner's handle is open. The
  scanner also compares size and last-write metadata before and after hashing.
- Metadata comparison cannot eliminate every time-of-check/time-of-use race. A
  future quarantine or enforcement decision must revalidate file identity at
  the point of action and must not rely on a path alone.
- Logs contain paths, statuses, timing, and timestamps, but not file content or
  hashes. Paths can still be sensitive and require appropriate log access and
  retention controls.
- This milestone makes no malware verdict, which avoids presenting an unknown
  hash as safe. Reputation lookup belongs in milestone 2.

## Definition of done for milestone 1

- [x] SHA-256 is calculated correctly for known and empty files.
- [x] Large files are streamed rather than buffered entirely in memory.
- [x] Missing paths, directories, access failures, and I/O failures are handled.
- [x] Cancellation is supported.
- [x] Machine-readable output and structured operational logs are available.
- [x] Automated tests cover primary success and failure behavior.
- [x] Build and tests pass on the target development machine.

Once the last checkbox is verified, the next milestone is a versioned local
malware-hash database behind its own lookup interface. SQLite is the likely
starting store; the scanner should depend on the interface, not SQLite itself.
