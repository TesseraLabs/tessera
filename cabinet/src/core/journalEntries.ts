// Read-side parsing of already-recorded journal lines (the flat,
// chain-metadata-plus-payload JSON objects `Journal`/`Payload` in
// `crates/tessera_issuer/src/journal.rs` produce), for the CRL form's two
// conveniences: picking revocation candidates from past issuances, and
// pre-filling `last_crl_number` from this CA's own past CRLs. This is
// read-only, best-effort text parsing over lines the cabinet already holds
// in memory — the WASM core's `journal_verify` remains the sole authority
// on chain integrity; this module never validates the hash chain.

export interface IssuedEntry {
  seq: number;
  op: "issue_leaf" | "issue_ca";
  serialHex: string;
  subject: string;
  parentHex: string;
}

export interface CrlEntry {
  seq: number;
  crlNumber: number;
  parentHex: string;
}

interface ParsedLines {
  issued: IssuedEntry[];
  crls: CrlEntry[];
}

/** Parse every line, silently skipping ones that are not a recognised issuance record. */
export function parseJournalLines(lines: string[]): ParsedLines {
  const issued: IssuedEntry[] = [];
  const crls: CrlEntry[] = [];

  for (const line of lines) {
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof value !== "object" || value === null) continue;
    const record = value as Record<string, unknown>;
    const seq = record["seq"];
    const op = record["op"];
    if (typeof seq !== "number" || typeof op !== "string") continue;

    if (op === "issue_leaf" || op === "issue_ca") {
      const serial = record["serial"];
      const subject = record["subject"];
      const parent = record["parent"];
      if (typeof serial === "string" && typeof subject === "string" && typeof parent === "string") {
        issued.push({ seq, op, serialHex: serial, subject, parentHex: parent });
      }
    } else if (op === "issue_crl") {
      const crlNumber = record["crl_number"];
      const parent = record["parent"];
      if (typeof crlNumber === "number" && typeof parent === "string") {
        crls.push({ seq, crlNumber, parentHex: parent });
      }
    }
  }

  return { issued, crls };
}

/** Revocation candidates issued by the CA fingerprinted `issuerHex`, newest first. */
export function revocationCandidates(lines: string[], issuerHex: string): IssuedEntry[] {
  const { issued } = parseJournalLines(lines);
  return issued.filter((entry) => entry.parentHex === issuerHex).sort((a, b) => b.seq - a.seq);
}

/** The highest `crlNumber` this CA (fingerprinted `issuerHex`) has previously issued, or 0. */
export function lastCrlNumber(lines: string[], issuerHex: string): number {
  const { crls } = parseJournalLines(lines);
  let max = 0;
  for (const entry of crls) {
    if (entry.parentHex === issuerHex && entry.crlNumber > max) max = entry.crlNumber;
  }
  return max;
}
