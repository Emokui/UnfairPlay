#!/bin/zsh
set -eu
umask 077
cd -- "${0:A:h}"
TOOLS="${1:-}"
DEST="../UnfairPlay.app"
APP="../UnfairPlay.building.app"
mkdir -p build
rm -rf -- "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/Tools"
GO_TOOL="${DESK_GO_BINARY:-$PWD/build/go-runtime/go/bin/go}"
if [[ ! -x "$GO_TOOL" ]]; then GO_TOOL="$(command -v go)"; fi
PROJECT_DIR="$PWD"
(
  cd Vendor/ipatool
  CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod" "$GO_TOOL" build -ldflags '-X github.com/majd/ipatool/v2/cmd.version=2.7.0-desk.6' -o "$PROJECT_DIR/build/ipatool" .
)
(
  cd Vendor/unfairplay
  CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod" "$GO_TOOL" build -trimpath -o "$PROJECT_DIR/build/modelcheck" ./cmd/modelcheck
  if [[ -z "$TOOLS" ]]; then
    CLANG_MODULE_CACHE_PATH="$PROJECT_DIR/build/clang-cache" GOCACHE="$PROJECT_DIR/build/go-cache" GOMODCACHE="$PROJECT_DIR/build/go-mod" "$GO_TOOL" build -trimpath -o "$PROJECT_DIR/build/unfairplay" ./cmd/unfairplay
  fi
)
ENGINE="$PWD/build/unfairplay"
if [[ -n "$TOOLS" ]]; then ENGINE="$TOOLS/unfairplay"; fi
cp build/modelcheck build/ipatool "$ENGINE" "$APP/Contents/Resources/Tools/"
for binary in "$APP/Contents/Resources/Tools/modelcheck" "$APP/Contents/Resources/Tools/ipatool" "$APP/Contents/Resources/Tools/unfairplay"; do
  chmod 755 "$binary"
  codesign --force --sign - "$binary"
done
TOOL_SHA="$(shasum -a 256 "$APP/Contents/Resources/Tools/unfairplay" | cut -d ' ' -f 1)"
clang -mmacosx-version-min=15.0 -Wno-deprecated-declarations -DDESK_ROOT_ONLY -DUNFAIRPLAY_SHA256=\"${TOOL_SHA}\" Sources/authorize.c -framework Security -framework CoreFoundation -o build/root-helper
codesign --force --sign - build/root-helper
ROOT_SHA="$(shasum -a 256 build/root-helper | cut -d ' ' -f 1)"
clang -mmacosx-version-min=15.0 -Wno-deprecated-declarations -DROOT_HELPER_SHA256=\"${ROOT_SHA}\" -DUNFAIRPLAY_SHA256=\"${TOOL_SHA}\" Sources/authorize.c -framework Security -framework CoreFoundation -o build/authorize
clang -mmacosx-version-min=15.0 Sources/worker.c -o build/worker
xcrun swiftc -target arm64-apple-macos15.0 -swift-version 5 -O -parse-as-library Sources/*.swift -o build/UnfairPlayDesk -framework SwiftUI -framework AppKit -framework Security -module-cache-path build/module-cache
cp build/UnfairPlayDesk "$APP/Contents/MacOS/UnfairPlayDesk"
cp build/root-helper build/authorize build/worker "$APP/Contents/Resources/Tools/"
mkdir -p "$APP/Contents/Resources/Licenses"
cp Licenses/* "$APP/Contents/Resources/Licenses/"
cp Info.plist "$APP/Contents/Info.plist"
cp Assets/AppIcon.icns Assets/AppIcon.png "$APP/Contents/Resources/"
for binary in "$APP/Contents/Resources/Tools/authorize" "$APP/Contents/Resources/Tools/worker" "$APP/Contents/MacOS/UnfairPlayDesk"; do
  chmod 755 "$binary"
  codesign --force --sign - "$binary"
done
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
python3 - <<'PY'
from pathlib import Path
import shutil,os
new=Path('../UnfairPlay.building.app')
dest=Path('../UnfairPlay.app')
backup=Path('build/Previous-UnfairPlay.app')
if backup.exists():shutil.rmtree(backup)
if dest.exists():os.rename(dest,backup)
try:os.rename(new,dest)
except Exception:
 if backup.exists():os.rename(backup,dest)
 raise
PY
print "已生成：${DEST:A}"
