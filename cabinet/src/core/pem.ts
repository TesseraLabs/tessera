// A client-side port of the Rust core's `pem_or_der`
// (`crates/tessera_issuer_wasm/src/api.rs`): decode a PEM wrapper when
// present, pass DER through unchanged.
//
// Why the cabinet needs its own copy: `build_leaf_tbs`/`build_ca_tbs`/
// `assemble_and_verify` all depem their `parent_b64`/`issuer_b64` input
// internally, so passing either PEM or DER to them works either way. But
// `journal_append` does **not** — `Journal::record_leaf`/`record_ca`/
// `record_crl` (`crates/tessera_issuer/src/journal.rs`) hash whatever bytes
// they're given as the parent's fingerprint, with no depeming step. If the
// operator loaded a PEM parent certificate, journalling the raw PEM bytes
// would fingerprint the *file*, not the *certificate* — a different CA cert
// re-exported to PEM with different line wrapping would then journal a
// different fingerprint for the same key. Depeming once, client-side, right
// after the parent file is loaded, keeps the fingerprint (and CRL-issuer
// journal matching) meaningful regardless of what the operator uploaded.

/** Whether `bytes` looks like PEM text: the first non-whitespace byte is `-`. */
function looksLikePem(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d) continue;
    return byte === 0x2d; // '-'
  }
  return false;
}

/**
 * Return the certificate/CSR DER bytes: decode the PEM wrapper when `bytes`
 * looks like PEM text, otherwise pass `bytes` through unchanged.
 */
export function pemOrDer(bytes: Uint8Array): Uint8Array {
  if (!looksLikePem(bytes)) return bytes;

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  let body = "";
  let inBody = false;
  for (const rawLine of text.split(/\r\n|\r|\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("-----BEGIN")) {
      inBody = true;
    } else if (line.startsWith("-----END")) {
      break;
    } else if (inBody) {
      body += line;
    }
  }
  if (body.length === 0) {
    throw new Error("no PEM body found");
  }
  const binary = atob(body);
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) der[i] = binary.charCodeAt(i);
  return der;
}
