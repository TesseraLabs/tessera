// Checked-in placeholder type declarations for the generated
// `wasm-bindgen --target web` bindings. `build.sh` (step 2) deletes this
// whole directory and regenerates it from the real `tessera_issuer_wasm`
// crate, overwriting this file with wasm-bindgen's own (equivalent)
// declarations — this file exists only so `tsc`/`node --test` can resolve
// `../../wasm/tessera_issuer_wasm.js` (see `src/core/wasmBridge.ts`) without
// requiring a WASM build first. Keep it in sync with
// `crates/tessera_issuer_wasm/src/lib.rs` by hand; a drift here is caught
// immediately by `tsc` after the next real build replaces it.
//
// After running `build.sh` locally this file (and its `.js` sibling) is
// overwritten with the real generated bindings; restore the stub with
// `git checkout -- wasm/tessera_issuer_wasm.js wasm/tessera_issuer_wasm.d.ts`
// if you want to `tsc`/`node --test` again without rebuilding.

/** Initialises the WASM module; must be awaited once before any call below. */
export default function init(
  moduleOrPath?: { module_or_path?: unknown } | unknown,
): Promise<unknown>;

export function inspect_parent(input: string): string;
export function build_leaf_tbs(input: string): string;
export function build_ca_tbs(input: string): string;
export function build_crl_tbs(input: string): string;
export function inspect_csr(input: string): string;
export function assemble_and_verify(input: string): string;
export function journal_append(input: string): string;
export function journal_verify(input: string): string;
