#!/bin/bash
# Probe which NEPacketTunnelProvider override signatures the current SDK accepts.
# Prints PROBE <name>: MATCH ✅ or the compiler error — read the job log to learn
# the exact signature, then fix TunnelProvider.swift accordingly.
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

try_sig A 'override func startTunnel(_ options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig B 'override func startTunnel(with options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig C 'override func startTunnel(options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig D 'override func startTunnel(_ options: [String : Any], completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig E 'override func startTunnel(options: [String : Any]?) async throws { }'
try_sig F 'override func startTunnel(_ options: [String : Any]?) async throws { }'
try_sig S 'override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }'
try_sig T 'override func stopTunnel(_ reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }'

# Also dump the raw interface text for these methods (ERE grep, no backslash issues).
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
IFACE=$(find "$SDK/System/Library/Frameworks/NetworkExtension.framework" -name "arm64-apple-ios.swiftinterface" | head -1)
echo "interface: $IFACE"
if [ -n "$IFACE" ]; then
  grep -nE "func startTunnel|func stopTunnel" "$IFACE"
fi
exit 0
