// Checked-in placeholder for the generated `wasm-bindgen --target web`
// bindings — see `tessera_issuer_wasm.d.ts` in this directory for why this
// exists. `build.sh` overwrites this whole directory with the real
// generated module before bundling; nothing in the test suite calls these
// functions (they need a live WASM instance), so throwing is the correct
// behaviour for any caller that reaches this placeholder by mistake (e.g.
// running the dev server without having run `build.sh` first).

function notBuilt() {
  throw new Error(
    "tessera_issuer_wasm bindings are a placeholder — run cabinet/build.sh to generate the real WASM bindings",
  );
}

export default async function init() {
  notBuilt();
}

export function inspect_parent() {
  notBuilt();
}

export function build_leaf_tbs() {
  notBuilt();
}

export function build_ca_tbs() {
  notBuilt();
}

export function build_crl_tbs() {
  notBuilt();
}

export function inspect_csr() {
  notBuilt();
}

export function assemble_and_verify() {
  notBuilt();
}

export function journal_append() {
  notBuilt();
}

export function journal_verify() {
  notBuilt();
}
