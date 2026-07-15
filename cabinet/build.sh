#!/usr/bin/env bash
# Build the Tessera issuer cabinet: WASM core + TypeScript SPA -> cabinet/dist/.
#
# Contract for CI (tasks.md 7.1/7.6): running this script with no arguments
# from anywhere produces a complete, ready-to-serve `cabinet/dist/` — no
# other setup step is implied.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
wasm_out="$here/wasm"
dist="$here/dist"

echo "== 1/4  cargo build -p tessera_issuer_wasm --target wasm32-unknown-unknown --release"
( cd "$repo_root" && cargo build -p tessera_issuer_wasm --target wasm32-unknown-unknown --release )
wasm_artifact="$repo_root/target/wasm32-unknown-unknown/release/tessera_issuer_wasm.wasm"
if [[ ! -f "$wasm_artifact" ]]; then
  echo "error: expected WASM artifact not found at $wasm_artifact" >&2
  exit 1
fi

echo "== 2/4  wasm-bindgen --target web"
if ! command -v wasm-bindgen >/dev/null 2>&1; then
  # The CLI version must match the `wasm-bindgen` crate version pinned in
  # Cargo.lock exactly, or the generated glue and the compiled module
  # disagree on the ABI and fail at init with an opaque error.
  locked_version="$(grep -A1 '^name = "wasm-bindgen"$' "$repo_root/Cargo.lock" | grep '^version' | head -1 | sed -E 's/version = "([^"]+)"/\1/')"
  if [[ -z "$locked_version" ]]; then
    echo "error: wasm-bindgen-cli is not installed and the locked wasm-bindgen version could not be determined from Cargo.lock" >&2
    echo "       install it manually with: cargo install wasm-bindgen-cli --version <version-from-Cargo.lock> --locked" >&2
    exit 1
  fi
  echo "wasm-bindgen-cli not found; installing version $locked_version (matching Cargo.lock)"
  cargo install wasm-bindgen-cli --version "$locked_version" --locked
fi
installed_version="$(wasm-bindgen --version | awk '{print $2}')"
locked_version="$(grep -A1 '^name = "wasm-bindgen"$' "$repo_root/Cargo.lock" | grep '^version' | head -1 | sed -E 's/version = "([^"]+)"/\1/')"
if [[ -n "$locked_version" && "$installed_version" != "$locked_version" ]]; then
  echo "error: installed wasm-bindgen-cli $installed_version does not match Cargo.lock's wasm-bindgen $locked_version" >&2
  echo "       reinstall with: cargo install wasm-bindgen-cli --version $locked_version --locked --force" >&2
  exit 1
fi
rm -rf "$wasm_out"
mkdir -p "$wasm_out"
wasm-bindgen --target web --out-dir "$wasm_out" --out-name tessera_issuer_wasm "$wasm_artifact"

echo "== 3/4  npm ci && esbuild bundle"
( cd "$here" && npm ci )
rm -rf "$dist"
mkdir -p "$dist"
( cd "$here" && npx esbuild src/main.ts \
    --bundle \
    --format=esm \
    --target=es2022 \
    --minify \
    --sourcemap \
    --outfile="$dist/main.js" )
cp "$here/public/index.html" "$dist/index.html"
cp "$here/public/styles.css" "$dist/styles.css"
# The generated glue's default `init()` fetches
# `new URL('tessera_issuer_wasm_bg.wasm', import.meta.url)`; esbuild bundles
# that module into main.js verbatim (import.meta.url is a runtime construct,
# not rewritten), so at runtime `import.meta.url` is main.js's own URL — the
# .wasm binary must sit next to it, not in a wasm/ subdirectory.
cp "$wasm_out/tessera_issuer_wasm_bg.wasm" "$dist/tessera_issuer_wasm_bg.wasm"

echo "== 4/4  SHA-256 manifest"
( cd "$dist" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS )

echo
echo "Built $dist:"
du -sh "$dist" | awk '{print "  total size: "$1}'
( cd "$dist" && cat SHA256SUMS )
