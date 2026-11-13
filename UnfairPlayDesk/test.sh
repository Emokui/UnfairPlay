#!/bin/zsh
set -eu
umask 077
cd -- "${0:A:h}"
mkdir -p build
APP="${1:-$PWD/../UnfairPlay.app}"
if [[ $# -eq 0 && ! -d "$APP" ]]; then APP="/Applications/UnfairPlay.app"; fi
TOOL="$APP/Contents/Resources/Tools/unfairplay"
ROOT_SHA="$(shasum -a 256 "$APP/Contents/Resources/Tools/root-helper" | cut -d ' ' -f 1)"
TOOL_SHA="$(shasum -a 256 "$TOOL" | cut -d ' ' -f 1)"
clang -Wno-deprecated-declarations -DROOT_HELPER_SHA256=\"${ROOT_SHA}\" -DUNFAIRPLAY_SHA256=\"${TOOL_SHA}\" Tests/AuthorizationTests.c -framework Security -framework CoreFoundation -o build/AuthorizationTests
./build/AuthorizationTests "$TOOL"
clang Sources/worker.c -o build/worker
PROJECT_DIR="$PWD"
GO_TOOL="${DESK_GO_BINARY:-$PWD/build/go-runtime/go/bin/go}"
if [[ ! -x "$GO_TOOL" ]]; then GO_TOOL="$(command -v go)"; fi
(
 cd Vendor/ipatool
 CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod" "$GO_TOOL" build -o "$PROJECT_DIR/build/GoInputTest" "$PROJECT_DIR/Tests/GoInput/main.go"
)
xcrun swiftc -D DESK_TESTING -swift-version 5 -parse-as-library Sources/Core.swift Sources/Jobs.swift Sources/Runner.swift Sources/AccountStore.swift Tests/RunnerTests.swift -o build/RunnerTests -framework AppKit -framework Security -module-cache-path build/module-cache
DESK_WORKER="$PWD/build/worker" DESK_MODELCHECK="$APP/Contents/Resources/Tools/modelcheck" ./build/RunnerTests
