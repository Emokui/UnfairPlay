# UnfairPlay

UnfairPlay recovers a FairPlay model from an enrolled Mac and uses it to
decrypt personalized iOS IPAs. It is a standalone Go program.

It does not log in to Apple, buy apps, or download IPAs. You can use ipatool or
another downloader for that part.

## Legal and ethical use

Use UnfairPlay only with apps you lawfully acquired and accounts and devices
you control. It is intended for interoperability, preservation, and authorized
research. The authors do not condone piracy, credential theft, copyright
infringement, or unauthorized distribution of decrypted apps.

## Build

```sh
go build -o unfairplay ./cmd/unfairplay
```

## Usage

First, sign in to the native Mac App Store. Install an iPhone or iPad app and
open it once. Download a matching encrypted IPA with the same Apple Account.

Set up reusable decryption once:

```sh
sudo ./unfairplay setup \
  --app /Applications/App.app \
  --ipa App.ipa
```

The saved model is private. It is tied to the Mac App Store enrollment, not to
one app, so it can decrypt other personalized IPAs from the same enrollment.

Decrypt another IPA:

```sh
./unfairplay decrypt --input AnotherApp.ipa
```

The default model directory is inside the user configuration directory. Set
`UNFAIRPLAY_MODEL_DIR` or pass `--model` to use another location.

IPAs with extensions and watch apps are decrypted in one pass. Test without
keeping plaintext with:

```sh
./unfairplay verify --input AnotherApp.ipa
```

### Convert an IPA for macOS

This requires an encrypted IPA personalized for the same Store enrollment as
your saved model. Convert it with:

```sh
./unfairplay convert-ipa-macos --input App.ipa
```

The default output is `App.macos.ipa`. Use `--output` to choose another path or
`--force` to replace an existing output.

The command uses a saved version-2 enrollment model. You can instead use a
matching private 16-byte credential:

```sh
chmod 600 credential.bin
./unfairplay convert-ipa-macos \
  --input App.ipa \
  --credential credential.bin
```

The conversion:

- validates and rewrites the personalized SINF into the macOS layout;
- preserves its app key, signature, rights, and other private fields;
- adds every SINF copy declared by Apple for encrypted frameworks and
  extensions; and
- leaves all Mach-O executables byte-identical and encrypted.

The result is still an IPA, not a macOS installer. A macOS iOS-app wrapper or
compatible installer must preserve this basic layout:

```text
App iOS.app/
  WrappedBundle -> Wrapper/App.app
  Wrapper/App.app
  Wrapper/iTunesMetadata.plist
```

The converted IPA and wrapper contain a private account license. Keep them
private. This feature does not decrypt, modify, re-sign, or bypass checks inside
the app. Apps may still reject macOS, require unavailable hardware, or depend on
services that are not present on macOS.

## Advanced commands

`collect` and `recover` expose the two setup stages for diagnostics and
archived captures. `doctor` checks a capture, IPA, or model. `profile` inspects
an arm64e fairplayd without executing it.

```sh
sudo ./unfairplay collect --app /Applications/App.app --ipa App.ipa --output App.capture
./unfairplay recover --capture App.capture --output App.recovery
```

Create a code profile for an exact fairplayd binary:

```sh
./unfairplay profile --binary /path/to/fairplayd.arm64e \
  --recovery-profile-output fairplayd.recovery-profile.gz
```

The profile contains code locations and import names. It contains no account
data and does not execute fairplayd. It helps add native support for new macOS
builds, but creating it alone does not enable decryption.

## FAQ

### What is an enrollment?

An enrollment is the FairPlay state created when an Apple Account uses the Mac
App Store on a Mac. It links the account, Mac, and FairPlay selector. `setup`
turns that state into a reusable private model.

### What are SINF, SUPF, SIDB, and SC Info?

- **Personalized SINF:** an app license created for one Store enrollment. It
  identifies the enrollment and protects the app-specific key.
- **SUPF:** per-executable records used to derive keys and IVs for encrypted
  Mach-O pages. Apps, extensions, frameworks, and watch apps may each have one.
- **`SC_Info`:** the directory inside an installed app or IPA that contains its
  SINF and SUPF license files.
- **System `SC Info`:** the private Mac FairPlay state directory. Its SIDB and
  SIDS files contain enrollment state, not app content.

These files are private. Do not publish or share them.

### Do I need to run setup for every app?

No. One model can decrypt different IPAs personalized for the same enrollment.
Each app still has its own key inside its personalized SINF.

### Why might another macOS build fail?

Apple changes fairplayd code and state layouts between builds. UnfairPlay fails
closed when a path is not verified. It never publishes a recovered model until
the matching IPA decrypts and passes validation.

Patches and test reports are welcome. Include the macOS build, fairplayd
SHA-256, UnfairPlay commit, and complete error. Never share SIDB, SINF, hardware
identity, enrollment models, decrypted apps, or Apple credentials.

### Can decryption run on another operating system?

Yes. Collection must start on an enrolled Mac. You can either run `setup` on
that Mac and securely copy the resulting model, or copy a complete private
`collect` bundle and run `recover` elsewhere. The bundle contains the installed
license files, system SC Info state, built-in IOMACAddress, matching IPA, macOS
build metadata, and hash-checked fairplayd reference bytes.

The recovered model and personalized IPAs can then be used on macOS or Linux;
fairplayd is never executed. Windows builds compile, but Windows decryption is
not enabled until equivalent private-file permission checks are implemented.

## Support

Verified enrollment contracts: `25G83`, `26A428`/`26A434`, and `26B118`.
`25G83` and `26B118` use the portable semantic evaluator; native fairplayd
execution is not required. Unknown arm64e builds are accepted only when model
recovery and full IPA validation succeed.

The evaluator source build is recorded for audit purposes. UnfairPlay does not
load or run that fairplayd binary during recovery.

macOS arm64 and Linux amd64/arm64 are supported. Windows is compile-tested but
cannot yet enforce the required private-file permissions.

The IPA, installed app, Mac state, hardware identity, and model must belong to
the same enrollment. Account or selector mismatches are rejected.

Keep capture and model files private. Do not share SIDB, SINF, hardware data,
recovery models, or decrypted apps. Decrypted IPAs are analysis files and need
signing before installation.

## Releases

Run the private control matrix in [QA.md](QA.md) before tagging a release.

Tags matching `v*` publish binaries and `SHA256SUMS` through GitHub Actions.
Tags such as `v0.2.0-rc.1` create prereleases.

## License

MIT. Third-party notices are in `NOTICE`, `LICENSE-DARKPHOENIX.txt`, and
`LICENSE-MACOSFAIRFREE.txt`.
