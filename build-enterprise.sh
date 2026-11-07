#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# V2GEN — ENTERPRISE build: a fully-signed, install-anywhere IPA.
#
# Signs with an In-House (enterprise) certificate pair that carries the
# packet-tunnel-provider entitlement — the ONLY kind of signing besides a
# paid developer team that can ever show the "Add VPN Configuration"
# popup (free Apple IDs are denied the entitlement by Apple, no matter
# what the side-loader does).
#
# The pair (verified against the profiles shipped with this build):
#   app    profile → com.ctq.qmc.yiban.produc   (packet-tunnel + vpn.api)
#   tunnel profile → com.ctq.qmc.yiban.product  (packet-tunnel)
#   "produc" + "t" = "product" — a valid app→extension prefix pair, SAME
#   team (JSVM68ZU8Z), so iOS accepts both bundles in one install.
#
#   ./build-enterprise.sh    → build/V2GEN-Enterprise.ipa
#
# Environment (set by CI from repo secrets, or locally):
#   ENT_P12               path to the .p12 (iPhone Distribution)
#   ENT_P12_PASS          its password
#   ENT_APP_PROFILE       app .mobileprovision
#   ENT_TUNNEL_PROFILE    tunnel .mobileprovision
#   ENT_APP_BUNDLE_ID     default com.ctq.qmc.yiban.produc
#   ENT_TUNNEL_BUNDLE_ID  default com.ctq.qmc.yiban.product
#
# Requirements: macOS with Xcode 26+, xcodegen, python3.
# The archive itself is built UNSIGNED (CODE_SIGNING_ALLOWED=NO); this
# script then signs both bundles with real codesign identities and embeds
# the matching profiles. Entitlements are extracted VERBATIM from each
# profile — the signature can then never ask for anything the profile
# does not grant (the #1 cause of "Killed: 9" after enterprise signing).
# No App Groups in these profiles: the app was built for that — the
# connect command rides the VPN profile's providerConfiguration, live
# stats/hot-swap degrade gracefully (see TunnelController / V2GenIPC).
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

APP_ID="${ENT_APP_BUNDLE_ID:-com.ctq.qmc.yiban.produc}"
TUN_ID="${ENT_TUNNEL_BUNDLE_ID:-com.ctq.qmc.yiban.product}"
P12="${ENT_P12:?ENT_P12 (path to .p12) required}"
P12_PASS="${ENT_P12_PASS:?ENT_P12_PASS required}"
APP_PROFILE="${ENT_APP_PROFILE:?ENT_APP_PROFILE (app .mobileprovision) required}"
TUN_PROFILE="${ENT_TUNNEL_PROFILE:?ENT_TUNNEL_PROFILE (tunnel .mobileprovision) required}"

for f in "$P12" "$APP_PROFILE" "$TUN_PROFILE"; do
  [ -f "$f" ] || { echo "missing input: $f" >&2; exit 1; }
done
command -v xcodegen >/dev/null || { echo "xcodegen not found — brew install xcodegen" >&2; exit 1; }

echo "── 1/7  Bundle ids (profile-pair)"
echo "      app    → $APP_ID"
echo "      tunnel → $TUN_ID"
# Tunnel MUST be the app id plus a suffix — Apple's extension rule.
case "$TUN_ID" in
  "$APP_ID"*) : ;;
  *) echo "ERROR: tunnel id must extend the app id (Apple extension rule)" >&2; exit 1 ;;
esac
# Rewrite the project's bundle ids (tunnel line first — it contains the
# app id as a prefix; the anchored app pattern can never touch it).
cp project.yml project.yml.bak
sed -i '' \
  -e "s|PRODUCT_BUNDLE_IDENTIFIER: xyz.v2gen.app.tunnel|PRODUCT_BUNDLE_IDENTIFIER: $TUN_ID|" \
  -e "s|PRODUCT_BUNDLE_IDENTIFIER: xyz.v2gen.app\$|PRODUCT_BUNDLE_IDENTIFIER: $APP_ID|" \
  project.yml
trap 'mv -f project.yml.bak project.yml' EXIT

echo "── 2/7  xcodegen + archive (Release, unsigned)"
xcodegen generate
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
grep "error:" build/xcodebuild.log | sort -u | head -30 || true
tail -4 build/xcodebuild.log
[ "$XCB_STATUS" -eq 0 ] || { echo "archive failed ($XCB_STATUS)" >&2; exit "$XCB_STATUS"; }

APP="build/V2GEN.xcarchive/Products/Applications/V2GEN.app"
APPEX="$APP/PlugIns/V2GEN-Tunnel.appex"
[ -d "$APP" ]  || { echo "no $APP" >&2; exit 1; }
[ -d "$APPEX" ] || { echo "no $APPEX" >&2; exit 1; }

rm -rf build/Payload
mkdir -p build/Payload
cp -R "$APP" build/Payload/
APP="build/Payload/V2GEN.app"
APPEX="$APP/PlugIns/V2GEN-Tunnel.appex"

echo "── 3/7  Entitlements — verbatim from each profile"
python3 - "$APP_PROFILE" build/app.entitlements <<'PY'
import plistlib, sys
raw = open(sys.argv[1], "rb").read()
xml = raw[raw.find(b"<?xml"):raw.rfind(b"</plist>") + 8]
plistlib.dump(plistlib.loads(xml)["Entitlements"], open(sys.argv[2], "wb"))
PY
python3 - "$TUN_PROFILE" build/tunnel.entitlements <<'PY'
import plistlib, sys
raw = open(sys.argv[1], "rb").read()
xml = raw[raw.find(b"<?xml"):raw.rfind(b"</plist>") + 8]
plistlib.dump(plistlib.loads(xml)["Entitlements"], open(sys.argv[2], "wb"))
PY
echo "      app:    $(grep -c '<key>' build/app.entitlements) keys"
echo "      tunnel: $(grep -c '<key>' build/tunnel.entitlements) keys"

echo "── 4/7  Keychain + identity"
KC=build/sign.keychain
KC_PASS="$(openssl rand -hex 24)"
security create-keychain -p "$KC_PASS" "$KC" >/dev/null
security list-keychains -d user -s "$KC" $(security list-keychains -d user | tr -d '"')
security set-keychain-settings -t 3600 "$KC"
security unlock-keychain -p "$KC_PASS" "$KC"
security import "$P12" -k "$KC" -P "$P12_PASS" -T /usr/bin/codesign >/dev/null 2>&1
security set-key-partition-list -S apple-tool:,apple: -s -k "$KC_PASS" "$KC" >/dev/null
IDENTITY="$(security find-identity -v -p codesigning "$KC" | grep "iPhone Distribution" | head -1 | awk '{print $2}')"
[ -n "$IDENTITY" ] || { echo "no iPhone Distribution identity in $P12" >&2; exit 1; }
security find-identity -v -p codesigning "$KC" | head -2

echo "── 5/7  Embed profiles + sign (inner → outer)"
cp "$APP_PROFILE" "$APP/embedded.mobileprovision"
cp "$TUN_PROFILE" "$APPEX/embedded.mobileprovision"
codesign --force --sign "$IDENTITY" \
  --entitlements build/tunnel.entitlements \
  "$APPEX"
codesign --force --sign "$IDENTITY" \
  --entitlements build/app.entitlements \
  "$APP"

echo "── 6/7  Verify"
codesign --verify --strict "$APPEX" && echo "      appex signature: OK"
codesign --verify --strict --deep "$APP" && echo "      app signature: OK (deep)"
PLIST_BUDDY=/usr/libexec/PlistBuddy
APP_PLIST_ID=$($PLIST_BUDDY -c "Print :CFBundleIdentifier" "$APP/Info.plist")
APEX_PLIST_ID=$($PLIST_BUDDY -c "Print :CFBundleIdentifier" "$APPEX/Info.plist")
echo "      app CFBundleIdentifier    → $APP_PLIST_ID"
echo "      appex CFBundleIdentifier  → $APEX_PLIST_ID"
[ "$APP_PLIST_ID" = "$APP_ID" ]    || { echo "app bundle id mismatch" >&2; exit 1; }
[ "$APEX_PLIST_ID" = "$TUN_ID" ]   || { echo "appex bundle id mismatch" >&2; exit 1; }

echo "── 7/7  IPA"
rm -f build/V2GEN-Enterprise.ipa
( cd build && zip -qry V2GEN-Enterprise.ipa Payload )
security delete-keychain "$KC" >/dev/null 2>&1 || true
SIZE=$(du -h build/V2GEN-Enterprise.ipa | cut -f1)
echo ""
echo "✅ build/V2GEN-Enterprise.ipa  ($SIZE)"
echo ""
echo "Install: 3uTools (Windows) / iMazing / Apple Configurator (Mac) install"
echo "it AS-IS. NEVER let AltStore/Sideloadly/ESign touch it — they RE-SIGN"
echo "and destroy the enterprise signature (and the VPN entitlement with it)."
