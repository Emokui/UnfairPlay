# UnfairPlay desktop patches

Base: ipatool 2.8.0 desktop branch. CLI version: `2.8.0-desk.9`.

Selected v2.8.1 changes: compact ARM64 Apple assets and legacy cache migration, process-local bundle reuse, shared immutable Mach-O preparation, bounded Unicorn JIT buffer, restore-image User-Agent/read-ahead, and authentication dialog response handling. Existing desktop authentication, account isolation, free-license acquisition, and purchased-app downloads remain.

Desktop changes:

- Lazy authenticated AEA prefix indexing; append-only, SHA-256-checked journal for small public restore-image reads (64 MiB maximum). No account credentials or app content in the journal. Cold preparation has a 60-minute limit; each remote image request has a 45-second limit. Apple asset and Unicorn preparation are serialized across processes.
- Warm Apple assets before starting authentication/ticket deadlines. Preserve child cancellation/deadline errors instead of silently entering legacy fallback. Framework-backed API preparation and execution are bounded.
- Direct HTTP for signed file URLs, artwork (bounded to 8 MiB) and public ZIP ranges; no Store VM or account cookie jar. File bodies have a 45-second idle limit. IPA transfer can resume once after a transient interruption.
- `download --expected-account` checks the already-loaded account and removes the GUI's redundant preflight process.
- ZIP patching replaces matching metadata/artwork/SINF entries and suppresses duplicate incoming SINF paths.

Default ad-hoc signing does not provide a permanent keychain application identity across changed builds. The desktop build script optionally accepts an existing signing identity; keychain access rules are not weakened. Recoverable passwords remain inside the existing protected credential backend.

Automated regression suites, `go vet`, signature checks, and `--self-check` are executed locally; live Apple account authentication, App Store downloads, and privileged model setup remain user-verified.


## Store authentication & download hardening (desk.9)

- Separate general machine Anisette (`machine`) and Store AMD (`store`) states in `anisette-v4`, clear stale `RoutingInfo` on Store provisioning, persist only device identity until Store provisioning succeeds, skip redundant `StoreAMDHeaders` VM opens on non-Store state, and automatically refresh login when Store AMD provisioning is absent without invalidating cached `kbsync`, wasting `kbsync` VMs, or falling back to `volumeStore`.
- Reuse a single `sap.Signer` across `RP`/`SP` steps within one `nativeLogin`, reuse fetched `urlBag` responses for the same hardware GUID within one process, and pass loader-verified SHA-256 digests into `machimage.OpenSharedVerified` to avoid rehashing pinned frameworks per VM open.
- Clone caller metadata maps safely in `writeMetadata` (including `nil` metadata), validate `volumeStore` and versioned `redownload` responses against requested app/bundle/version identifiers, propagate cancellation to IPA HTTP range metadata reads, and pass command context, `--expected-account` checks, plus interactive 2FA/storefront refresh across subcommands.


## Profile session encryption (desk.8)

Named desktop profiles lazily store `account`, `anisette-v4`, and `kbsync-v1` in an AES-256-GCM encrypted `session-v1.enc` file. The existing per-profile keychain service stores a fixed 32-byte `session-master-v1` key, read once per keychain instance in standalone CLI use. In the GUI the desktop process caches the key per account and services one request over an inherited private socket while the CLI holds the session lock. A file lock serializes read/modify/write operations across CLI processes, and writes use a private temporary file and atomic rename.

Migration reads the old account and device state, skips the old reproducible kbsync cache, verifies committed ciphertext, and then removes all three legacy entries. A pending cleanup flag permits resuming interrupted migration. Revoke removes both formats without decrypting or reading the master key. A cached writer fails after concurrent revocation instead of recreating an orphaned session. macOS keychain reads preserve authorization errors instead of treating them as absent credentials. Unprofiled CLI sessions keep the existing storage format.
