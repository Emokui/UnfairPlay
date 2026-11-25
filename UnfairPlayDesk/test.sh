#!/bin/zsh
set -eu
umask 077
cd -- "${0:A:h}"
mkdir -p build
export MACOSX_DEPLOYMENT_TARGET=14.0
export CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=14.0"
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=14.0"
APP="${1:-$PWD/../UnfairPlay.app}"
if [[ $# -eq 0 && ! -d "$APP" ]]; then APP="/Applications/UnfairPlay.app"; fi
TOOL="$APP/Contents/Resources/Tools/unfairplay"
ROOT_SHA="$(shasum -a 256 "$APP/Contents/Resources/Tools/root-helper" | cut -d ' ' -f 1)"
TOOL_SHA="$(shasum -a 256 "$TOOL" | cut -d ' ' -f 1)"
clang -Wall -Wextra -Wno-deprecated-declarations -DROOT_HELPER_SHA256=\"${ROOT_SHA}\" -DUNFAIRPLAY_SHA256=\"${TOOL_SHA}\" Tests/AuthorizationTests.c -framework Security -framework CoreFoundation -o build/AuthorizationTests
./build/AuthorizationTests "$TOOL"
clang -Wall -Wextra Sources/worker.c -o build/worker
PROJECT_DIR="$PWD"
GO_TOOL="${DESK_GO_BINARY:-$PWD/build/go-runtime/go/bin/go}"
if [[ ! -x "$GO_TOOL" ]]; then GO_TOOL="$(command -v go)"; fi
(
 cd Vendor/ipatool
 export CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod"
 "$GO_TOOL" vet ./cmd ./pkg/... ./internal/...
 "$GO_TOOL" test -count=1 ./cmd ./pkg/keychain ./pkg/http ./pkg/appstore
 "$GO_TOOL" test -count=1 ./internal/cachelock ./internal/store ./internal/store/emulator ./internal/store/profile ./internal/storeauth
 "$GO_TOOL" test -count=1 ./internal/sap/assets ./internal/sap/machimage ./internal/sap/machine ./internal/sap/unicorn
 if [[ "${DESK_LIVE_SAP_TEST:-0}" == "1" ]]; then
  "$GO_TOOL" test -count=1 ./internal/sap
 else
  "$GO_TOOL" test -count=1 -skip '^TestSignerIntegration$' ./internal/sap
 fi
 "$GO_TOOL" build -o "$PROJECT_DIR/build/GoInputTest" "$PROJECT_DIR/Tests/GoInput/main.go"
)
(
 cd Vendor/unfairplay
 CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod" "$GO_TOOL" test -count=1 -run 'TestIPAEncryptionStatus|TestIPAMetadataBytes|TestWriteMultiSINFArchive|TestInspectIPAFile|TestModelOnlyValidation|TestModelSelectorMetadataOutput' ./internal/fairplay ./cmd/modelcheck
)
xcrun swiftc -target arm64-apple-macos14.0 -D DESK_TESTING -swift-version 5 -parse-as-library Sources/StorefrontRegions.swift Sources/DownloadCatalog.swift Sources/Core.swift Sources/Jobs.swift Sources/TaskDiagnostic.swift Sources/DownloadedIPA.swift Sources/IPAStatus.swift Sources/IPAFolderScan.swift Sources/IPAReportData.swift Sources/UpdateChecker.swift Sources/SessionKeyChannel.swift Sources/Runner.swift Sources/AccountStore.swift Tests/RunnerTests.swift -o build/RunnerTests -framework AppKit -framework Security -module-cache-path build/module-cache
DESK_WORKER="$PWD/build/worker" DESK_MODELCHECK="$APP/Contents/Resources/Tools/modelcheck" DESK_IPATOOL="$APP/Contents/Resources/Tools/ipatool" ./build/RunnerTests
