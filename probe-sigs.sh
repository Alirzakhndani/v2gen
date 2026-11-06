#!/bin/bash
# Probe round 3: the ObjC header + apinotes are the source of truth.
set +e

try_sig() {
  local name="$1"
  local body="$2"
  printf 'import NetworkExtension\nclass Probe%s: NEPacketTunnelProvider {\n%s\n}\n' "$name" "$body" > "/tmp/probe_$name.swift"
  if xcrun -sdk iphoneos swiftc -target arm64-apple-ios26.0 -typecheck "/tmp/probe_$name.swift" 2> "/tmp/probe_$name.err"; then
    echo "PROBE $name: MATCH ✅"
  else
    echo "PROBE $name: NO — $(grep -m1 'error:' "/tmp/probe_$name.err" | cut -c1-150)"
  fi
}

# @Sendable hypothesis: startTunnel's completion may now be @Sendable.
try_sig M 'override func startTunnel(_ options: [String : Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }'
try_sig N 'override func startTunnel(with options: [String : Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }'
try_sig O 'override func startTunnel(options: [String : Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }'

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
FW="$SDK/System/Library/Frameworks/NetworkExtension.framework"

echo "--- NEPacketTunnelProvider.h: startTunnel/stopTunnel ---"
grep -n "startTunnel\|stopTunnel" "$FW/Headers/NEPacketTunnelProvider.h" 2>/dev/null | head -12

echo "--- NEProvider.h: startTunnel ---"
grep -n "startTunnel" "$FW/Headers/NEProvider.h" 2>/dev/null | head -6

echo "--- full startTunnel decl in header ---"
HDR="$FW/Headers/NEPacketTunnelProvider.h"
if [ ! -f "$HDR" ]; then HDR="$FW/Headers/NEProvider.h"; fi
LN=$(grep -n "startTunnel" "$HDR" 2>/dev/null | head -1 | cut -d: -f1)
if [ -n "$LN" ]; then
  END=$((LN + 10))
  sed -n "${LN},${END}p" "$HDR"
fi

echo "--- apinotes ---"
find "$SDK" -name "NetworkExtension.apinotes" 2>/dev/null | while read -r f; do
  echo "== $f"
  grep -n -B1 -A6 "startTunnel" "$f"
done

echo "--- all apinotes files mentioning startTunnel ---"
find "$SDK/System/Library/Frameworks" -name "*.apinotes" 2>/dev/null | while read -r f; do
  if grep -q "startTunnel" "$f" 2>/dev/null; then
    echo "== $f"
    grep -n -B2 -A8 "startTunnel" "$f"
  fi
done
exit 0
