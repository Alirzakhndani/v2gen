#!/bin/bash
# Probe round 2: find the REAL startTunnel signature in this SDK.
set +e

try_sig() {
  local name="$1"
  local body="$2"
  printf 'import NetworkExtension\nclass Probe%s: NEPacketTunnelProvider {\n%s\n}\n' "$name" "$body" > "/tmp/probe_$name.swift"
  if xcrun -sdk iphoneos swiftc -target arm64-apple-ios26.0 -typecheck "/tmp/probe_$name.swift" 2> "/tmp/probe_$name.err"; then
    echo "PROBE $name: MATCH ✅"
  else
    echo "PROBE $name: NO — $(grep -m1 'error:' "/tmp/probe_$name.err" | cut -c1-160)"
  fi
}

try_sig G 'override func start(with options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig H 'override func startTunnel(withOptions options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig I 'override func startTunnel(options: [String : Any], completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig J 'override func startTunnel(with options: [String : Any], completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig K 'override func start(_ options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig L 'override func startTunnel(_ options: NSDictionary?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig S 'override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }'

# The raw truth: grep the swiftinterface (arm64e!) with ERE.
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
IFACE=$(find "$SDK/System/Library/Frameworks/NetworkExtension.framework" -name "*.swiftinterface" | head -1)
echo "interface: $IFACE"
if [ -n "$IFACE" ]; then
  echo "--- startTunnel / stopTunnel / class decls ---"
  grep -nE "func startTunnel|func stopTunnel|func start\(|class NEPacketTunnelProvider|class NEProvider" "$IFACE"
  echo "--- NEPacketTunnelProvider block (first 40 lines) ---"
  START=$(grep -n "class NEPacketTunnelProvider" "$IFACE" | head -1 | cut -d: -f1)
  if [ -n "$START" ]; then
    END=$((START + 40))
    sed -n "${START},${END}p" "$IFACE"
  fi
fi
exit 0
