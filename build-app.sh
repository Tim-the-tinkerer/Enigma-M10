#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

LAUNCH=true
for arg in "$@"; do
    case "${arg}" in
        --no-launch) LAUNCH=false ;;
    esac
done

APP="EnigmaM10.app"
BUNDLE_ID="com.tim.enigmam10"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' AppInfo.plist 2>/dev/null || true)"
VERSION="${VERSION:-?}"

if [[ ! -f Assets/AppIcon.icns ]]; then
    echo "Generating app icon..."
    swift Scripts/GenerateAppIcon.swift
fi

echo "Building Enigma – M 10 ${VERSION} (release)..."
swift build -c release --product EnigmaM10

BIN=".build/release/EnigmaM10"
if [[ ! -x "${BIN}" ]]; then
    echo "error: expected binary not found at ${BIN}" >&2
    exit 1
fi

echo "Assembling ${APP}..."
rm -rf "${APP}"
mkdir -p "${APP}/Contents/MacOS"
mkdir -p "${APP}/Contents/Resources"
cp "${BIN}" "${APP}/Contents/MacOS/EnigmaM10"
chmod +x "${APP}/Contents/MacOS/EnigmaM10"
cp AppInfo.plist "${APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleGetInfoString Enigma – M 10 ${VERSION}" \
    "${APP}/Contents/Info.plist" 2>/dev/null || true

if [[ -f Assets/AppIcon.icns ]]; then
    cp Assets/AppIcon.icns "${APP}/Contents/Resources/"
fi

echo "Signing ${APP}..."
xattr -cr "${APP}" 2>/dev/null || true
codesign --force --sign - --identifier "${BUNDLE_ID}" --timestamp=none "${APP}/Contents/MacOS/EnigmaM10"
codesign --force --sign - --identifier "${BUNDLE_ID}" --timestamp=none "${APP}"

plutil -lint "${APP}/Contents/Info.plist" >/dev/null
codesign --verify --verbose=2 "${APP}" 2>/dev/null || codesign --verify "${APP}"

if [[ -x /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister ]]; then
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$(pwd)/${APP}" 2>/dev/null || true
fi

echo "Done: ${APP} (v${VERSION})"
if [[ "${LAUNCH}" == "true" ]]; then
    pkill -x EnigmaM10 2>/dev/null || true
    sleep 0.2
    echo "Launching..."
    open "${APP}"
fi
