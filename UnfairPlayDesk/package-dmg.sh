#!/bin/zsh
set -eu
umask 022
cd -- "${0:A:h}"
APP="${1:-../UnfairPlay.app}"
if [[ $# -eq 0 && ! -d "$APP" ]]; then APP="/Applications/UnfairPlay.app"; fi
mkdir -p build
VERSION="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist")"
OUTPUT="${PWD:h}/UnfairPlay-${VERSION}.dmg"
STAGE="$(mktemp -d "$PWD/build/dmg-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
codesign --verify --deep --strict "$APP"
ditto "$APP" "$STAGE/UnfairPlay.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname UnfairPlay -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$OUTPUT"
hdiutil verify "$OUTPUT"
print "已生成：$OUTPUT"
