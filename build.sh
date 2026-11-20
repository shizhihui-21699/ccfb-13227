#!/usr/bin/env bash
# Rebuilds the WebAssembly engine and refreshes the embedded samples.
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$here"
cd "$here/engine"

echo "==> go test"
go test ./...

echo "==> building wasm engine"
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "$root/web/audit.wasm" ./cmd/wasmaudit

echo "==> copying wasm_exec.js"
goroot="$(go env GOROOT)"
if [ -f "$goroot/lib/wasm/wasm_exec.js" ]; then
  cp "$goroot/lib/wasm/wasm_exec.js" "$root/web/wasm_exec.js"
elif [ -f "$goroot/misc/wasm/wasm_exec.js" ]; then
  cp "$goroot/misc/wasm/wasm_exec.js" "$root/web/wasm_exec.js"
else
  echo "warning: wasm_exec.js not found under $goroot" >&2
fi

echo "==> embedding samples"
node "$root/web/build-samples.js"

size=$(wc -c < "$root/web/audit.wasm" | tr -d ' ')
echo "==> done. audit.wasm = $((size / 1024)) KiB"
echo "    serve: (cd $root/web && python3 -m http.server 8080)"
