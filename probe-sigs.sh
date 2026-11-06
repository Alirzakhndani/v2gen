#!/bin/bash
# Probe round 4: confirm the exact label with the correct NSObject dictionary type.
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

try_sig P1 'override func startTunnel(_ options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig P2 'override func startTunnel(with options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }'
try_sig P3 'override func startTunnel(_ options: [String : NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }'
try_sig P4 'override func startTunnel(with options: [String : NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }'
exit 0
