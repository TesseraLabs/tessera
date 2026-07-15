// The lowercase-hex SHA-256 "parent" fingerprint the journal records
// (`fingerprint()` in `crates/tessera_issuer/src/journal.rs`), computed
// client-side so the cabinet can match a loaded CA certificate against its
// own past journal entries (CRL-issuer scoping — see `core/journalEntries.ts`).

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Lowercase-hex SHA-256 of `der`, matching the journal's own fingerprint format. */
export async function sha256HexOfDer(der: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", der);
  return bytesToHex(new Uint8Array(digest));
}
