#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# V2GEN — build the installable IPA (unsigned / ad-hoc).
#
#   ./build-ipa.sh            → build/V2GEN.ipa
#
# Requirements on the Mac: Xcode 26+, xcodegen (brew install xcodegen).
#
# The archive builds with CODE_SIGNING_ALLOWED=NO, then the bundles are
# signed AD-HOC (codesign -) WITH the entitlements files embedded — that is
# what free side-loaders (Sideloadly / AltStore) read and carry over when
# they re-sign with your personal Apple ID. The app group is resolved at
# RUNTIME from the embedded provisioning profile (see Shared/V2GenIPC.swift),
# so whatever group name the free signer provisions "just works".
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

echo "── 1/5  xcodegen"
if ! command -v xcodegen >/dev/null; then
  echo "xcodegen not found — install it first:  brew install xcodegen" >&2
  exit 1
fi
xcodegen generate

echo "── 2/5  Archive (Release, unsigned)"
rm -rf build
mkdir -p build
set +e
xcodebuild archive \
  -project V2GEN.xcodeproj \
  -scheme V2GEN \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath build/V2GEN.xcarchive \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  AD_HOC_CODE_SIGNING_ALLOWED=YES \
  > build/xcodebuild.log 2>&1
XCB_STATUS=$?
set -e
echo "── xcodebuild diagnostics — errors first ──"
grep "error:" build/xcodebuild.log | sort -u | head -30 || echo "(no error lines)"
echo "── xcodebuild log tail ──"
tail -6 build/xcodebuild.log
if [ "$XCB_STATUS" -ne 0 ]; then
  echo "xcodebuild archive failed with exit $XCB_STATUS" >&2
  exit "$XCB_STATUS"
fi

APP="build/V2GEN.xcarchive/Products/Applications/V2GEN.app"
if [ ! -d "$APP" ]; then
  echo "Archive did not produce $APP" >&2
  exit 1
fi
APPEX="$APP/PlugIns/V2GEN-Tunnel.appex"
if [ ! -d "$APPEX" ]; then
  echo "Archive is missing the tunnel extension ($APPEX)" >&2
  exit 1
fi

echo "── 3/5  Payload"
rm -rf build/Payload
mkdir -p build/Payload
cp -R "$APP" build/Payload/

echo "── 4/5  Ad-hoc sign with entitlements (keeps them through side-loaders)"
codesign --force --sign - \
  --entitlements V2GEN-Tunnel/V2GEN-Tunnel.entitlements \
  "build/Payload/V2GEN.app/PlugIns/V2GEN-Tunnel.appex/V2GEN-Tunnel"
codesign --force --sign - \
  --entitlements V2GEN/V2GEN.entitlements \
  "build/Payload/V2GEN.app/V2GEN"

echo "── 5/5  IPA"
rm -f build/V2GEN.ipa
cd build
zip -qry V2GEN.ipa Payload
cd ..
SIZE=$(du -h build/V2GEN.ipa | cut -f1)
echo ""
echo "✅ build/V2GEN.ipa  ($SIZE)"
echo ""
echo "Install (free, 7-day renewal):"
echo "  • Sideloadly (macOS/Windows) — drag the IPA, sign with your Apple ID"
echo "  • AltStore / SideStore — install via the IPA, auto-refresh on Wi-Fi"
echo "  • Xcode — open V2GEN.xcodeproj, select your team in BOTH targets, ⌘R"
echo "Details: INSTALL-fa.md"
