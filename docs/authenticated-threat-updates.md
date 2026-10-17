# Authenticated Threat-Intelligence Updates

Milestone 9 gives UtoAegis an authenticated, rollback-protected path for
updating its hash indicators and exact-byte signatures. It intentionally does
not fetch content from the network. An operator transfers a signed directory to
the endpoint and activates it with the CLI.

## Trust model

- A publisher signs the exact bytes of `manifest.json` with an ECDSA NIST P-256
  private key and SHA-256.
- Endpoints receive only the corresponding `PUBLIC KEY` PEM and map it to the
  manifest's key ID.
- The signature authenticates the manifest. The manifest authenticates the
  fixed payload names, byte lengths, and SHA-256 digests.
- A persistent highest-accepted sequence rejects the current sequence and every
  lower sequence, including after an operator rollback.
- Files are parsed with bounded, strict readers before activation. Unknown or
  duplicate JSON properties are rejected rather than ignored.
- The Windows service receives read-only access to the content store and public
  keys. Only an administrator or a future separately privileged updater should
  run `updates apply` or `updates rollback`.

The design protects against a compromised mirror, transfer path, or untrusted
bundle directory. It does not protect against a compromised signing key, kernel,
or local administrator. Protect public-key configuration from unauthorized
changes and keep private keys off monitored endpoints.

## Bundle format

A bundle is a directory containing exactly four regular, non-reparse-point
files with exact lowercase names:

```text
manifest.json
manifest.sig
indicators.jsonl
signatures.jsonl
```

`manifest.sig` contains one base64-encoded RFC 3279 DER ECDSA signature. The
signature covers the exact `manifest.json` bytes, including whitespace and
property order. No JSON canonicalization step is involved.

A version-one manifest has this shape:

```json
{
  "schemaVersion": 1,
  "algorithm": "ecdsa-p256-sha256",
  "sequence": 42,
  "version": "2026.10.17.1",
  "keyId": "production-2026",
  "publishedUtc": "2026-10-17T18:00:00.0000000+00:00",
  "expiresUtc": "2026-10-24T18:00:00.0000000+00:00",
  "contents": [
    {
      "kind": "hash-indicators",
      "sha256": "<64 lowercase hexadecimal characters>",
      "length": 1234
    },
    {
      "kind": "byte-signatures",
      "sha256": "<64 lowercase hexadecimal characters>",
      "length": 5678
    }
  ]
}
```

The bundle must contain exactly one descriptor of each kind. Version and key
identifiers are limited to 64 ASCII letters, digits, dots, dashes, or
underscores and must begin and end with a letter or digit. Payloads are limited
to 512 MiB by the manifest contract; the existing readers impose tighter
format-specific limits.

New activation accepts five minutes of clock skew and at most a 14-day validity
period by default. It rejects an update published too far in the future or
expired beyond that skew. An already-active or rollback version remains usable
after expiration as last-known-good content, and the service emits warning event
302 on startup.

## Publisher workflow

Use a dedicated offline signing system or organization-controlled signing
service for production. A development key may be generated with .NET for a
harmless test environment, but an unencrypted development PEM is not a
production key-management strategy.

The repository builder accepts a PKCS#8 ECDSA P-256 private-key PEM:

```powershell
pwsh ./scripts/windows/New-UtoAegisThreatBundle.ps1 `
  -IndicatorsPath 'D:\Reviewed\indicators.jsonl' `
  -SignaturesPath 'D:\Reviewed\signatures.jsonl' `
  -Version '2026.10.17.1' `
  -Sequence 42 `
  -KeyId 'production-2026' `
  -PrivateKeyPath 'D:\OfflineKeys\production-2026.private.pem' `
  -OutputDirectory 'D:\Bundles\2026.10.17.1' `
  -ValidityDays 7
```

The output directory must not already exist. The script copies both reviewed
feeds into a fresh staging directory, hashes those staged bytes, writes and
signs the manifest, and then renames the completed directory into place. It
does not print or copy the private key.

Protect the publisher's sequence allocation against reuse. A simple deployment
should maintain one durable counter per update channel and reserve each value
before publishing. Never reset a production sequence because an endpoint has
rolled back.

## Endpoint activation

Transfer the completed bundle and the public key through your normal deployment
system. Applying a bundle requires every trusted key that should be accepted:

```powershell
$cli = 'C:\Program Files\UtoAegis\tools\utoaegis.exe'
$store = 'C:\ProgramData\UtoAegis\Content'
$key = 'production-2026=C:\ProgramData\UtoAegis\Policy\production-2026.public.pem'

& $cli updates apply --store $store --trusted-key $key 'D:\Incoming\2026.10.17.1'
& $cli updates status --store $store
```

Repeat `--trusted-key` during a key-rotation overlap. The loader accepts at most
32 unique key IDs, rejects private-key PEM labels, rejects reparse points, and
requires NIST P-256 public keys.

Activation performs these steps while holding an exclusive update lock:

1. Parse the strict manifest and verify its detached signature.
2. Enforce the time policy and monotonic sequence floor.
3. Copy each payload to a fresh same-volume staging directory while verifying
   its signed length and SHA-256 digest.
4. Parse every staged indicator and signature rule with existing bounded readers.
5. Build and query a fresh SQLite reputation database, then checkpoint it for
   read-only consumption.
6. Rename staging to its immutable version directory.
7. Atomically replace `state.json` so the new version becomes active.

A failure before step 7 leaves the previous pointer active. An uncommitted
version directory is removed on handled failures. State corruption fails closed;
it is never treated as an empty store because that would weaken rollback
protection.

## Rollback and recovery

After at least two successful activations, restore the previous version with:

```powershell
& $cli updates rollback --store $store --trusted-key $key
```

Rollback reverifies the previous manifest, signature, payloads, strict feed
syntax, and derived database before swapping the active and previous pointers.
It does not enforce the old expiration time because the explicit purpose is
last-known-good recovery. It preserves `highestAcceptedSequence`; after rolling
from sequence 43 back to 42, neither 42 nor 43 can be applied as a new update.
The next update must use sequence 44 or higher.

The service loads content only at startup. Apply or roll back the bundle, verify
`updates status`, then restart the service during a controlled change window.
If restart validation fails, the service does not begin monitoring with
unverified content.

## Service configuration

Managed content replaces direct `DatabasePath` and `SignaturePath` settings:

```json
{
  "UtoAegis": {
    "ContentStorePath": "C:\\ProgramData\\UtoAegis\\Content",
    "TrustedSigningKeys": [
      {
        "KeyId": "production-2026",
        "PublicKeyPath": "C:\\ProgramData\\UtoAegis\\Policy\\production-2026.public.pem"
      }
    ]
  }
}
```

Do not also set `DatabasePath` or `SignaturePath`. The content store must exist,
must be outside the monitored and installation trees, and cannot be a reparse
point or filesystem root. Public keys must exist outside the content store and
service-writable state. The installer grants the virtual service account read
access only.

Service startup rechecks the state reference, manifest signature, signed
payload hashes, strict feed syntax, and a database lookup. Event 104 records the
version, sequence, key, and expiration. Event 302 warns when last-known-good
content is expired.

## Key rotation and revocation

For planned rotation, configure old and new public keys, publish a higher
sequence signed by the new key, activate it, restart and observe the service,
then remove the old key after the rollback window closes. A rollback version
signed only by a removed key will be refused until that key is deliberately
restored to the trust configuration.

For key compromise, remove the affected public key, distribute a replacement
key through a separately trusted configuration channel, and publish a higher
sequence. Milestone 9 does not provide a signed key-revocation list or recover a
compromised private key automatically.

## Current limitations

- Bundle transport and scheduling are external operator responsibilities.
- Activation is atomic, but the running service does not live-reload content.
- Only the immediately previous version is addressable through rollback;
  older version directories are retained without an automatic prune policy.
- The anti-rollback floor is local state. Local-administrator or disk compromise
  remains within the trust boundary.
- ECDSA P-256/SHA-256 is the only accepted signature algorithm in schema 1.
- Trust-key changes are authenticated by host configuration controls rather
  than by the bundle format.
