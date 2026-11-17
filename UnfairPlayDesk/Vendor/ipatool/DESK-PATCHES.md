# UnfairPlay desktop patches

Base: ipatool 2.8.0 desktop branch. CLI version: `2.8.0-desk.7`.

Selected v2.8.1 changes: compact ARM64 Apple assets and legacy cache migration, process-local bundle reuse, shared immutable Mach-O preparation, bounded Unicorn JIT buffer, restore-image User-Agent/read-ahead, and authentication dialog response handling. Existing desktop authentication, account isolation, free-license acquisition, and purchased-app downloads remain.

Desktop changes:

- Lazy authenticated AEA prefix indexing; append-only, SHA-256-checked journal for small public restore-image reads (64 MiB maximum). No account credentials or app content in the journal. Cold preparation has a 60-minute limit; each remote image request has a 45-second limit. Apple asset and Unicorn preparation are serialized across processes.
- Warm Apple assets before starting authentication/ticket deadlines. Preserve child cancellation/deadline errors instead of silently entering legacy fallback. Framework-backed API preparation and execution are bounded.
- Direct HTTP for signed file URLs, artwork and public ZIP ranges; no Store VM or account cookie jar. File bodies have a 45-second idle limit. IPA transfer can resume once after a transient interruption.
- `download --expected-account` checks the already-loaded account and removes the GUI's redundant preflight process.
- ZIP patching replaces matching metadata/artwork/SINF entries and suppresses duplicate incoming SINF paths.

Default ad-hoc signing does not provide a permanent keychain application identity across changed builds. The desktop build script optionally accepts an existing signing identity; keychain access rules are not weakened. Recoverable passwords remain inside the existing protected credential backend.

This revision is compiled and packaged only; functional verification is left to the user as requested.
