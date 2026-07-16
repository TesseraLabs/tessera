// Inventory-snapshot format and verification (spec `issuer-cabinet` —
// "Инвентарь для форм — снапшот файлом с проверкой подписи"; design D9).
//
// # Format
//
// The snapshot file is JSON:
//
// ```json
// {
//   "payload_json": "<the exact UTF-8 text of the payload object below>",
//   "signature_b64": "<base64, or null for a manual/unsigned snapshot>"
// }
// ```
//
// `payload_json` is signed *as bytes*, not re-serialised: the verifier hashes
// exactly the string in `payload_json` (UTF-8), so there is no canonical-JSON
// ambiguity between the signer's and the cabinet's serialisers — any tool
// that can produce that exact string and sign it with ECDSA P-256 (raw
// `r || s`, per WebCrypto's default ECDSA signature encoding) over its
// SHA-256 digest produces a snapshot this module accepts. `payload_json`
// parses to:
//
// ```json
// {
//   "generated_at": 1750000000,
//   "hosts": [{"id": "sha256:...", "label": "north-01"}],
//   "users": ["ivanov"],
//   "roles": ["oper", "serv"],
//   "tags": [{"key": "region", "value": "north"}]
// }
// ```
//
// # Verification key
//
// The verification key is *not* derived from the parent certificate (the
// parent's key algorithm has no reason to be P-256, and coupling the two
// would make a snapshot re-verify differently every time the operator swaps
// parents). It is an operator-supplied JWK, entered once per session (see
// `state/sessionConfig.ts`) — the simple, honest option: a snapshot is valid
// only against whatever key the operator actually trusts *right now*, not
// whatever key happens to be embedded in the certificate on screen.
//
// An unsigned snapshot (`signature_b64: null`) is always accepted and
// labelled "manual" — the spec explicitly disallows blocking issuance on a
// missing snapshot.

export interface SnapshotHost {
  id: string;
  label?: string;
}

export interface SnapshotTag {
  key: string;
  value: string;
}

export interface SnapshotPayload {
  generated_at: number;
  hosts: SnapshotHost[];
  users: string[];
  roles: string[];
  tags: SnapshotTag[];
}

export interface SnapshotFile {
  payload_json: string;
  signature_b64: string | null;
}

/**
 * Serialise a payload assembled in the cabinet's own inventory constructor
 * into the same file shape a signed export uses, minus a signature (spec
 * `issuer-cabinet` — "Сборка инвентаря конструктором": collected inventory is
 * equivalent to an unsigned/manual snapshot). The result round-trips through
 * {@link acceptSnapshot} exactly like a hand-authored manual snapshot file —
 * there is no separate "constructed" code path in the acceptance logic, only
 * in how the JSON gets produced.
 */
export function buildManualSnapshot(payload: SnapshotPayload): SnapshotFile {
  return { payload_json: JSON.stringify(payload), signature_b64: null };
}

export type SnapshotOrigin = "signed" | "manual";

export interface AcceptedSnapshot {
  origin: SnapshotOrigin;
  payload: SnapshotPayload;
  ageSeconds: number;
}

export type SnapshotRejection =
  | { kind: "malformed"; message: string }
  | { kind: "bad_signature" }
  | { kind: "no_key" };

export type SnapshotResult =
  | { ok: true; snapshot: AcceptedSnapshot }
  | { ok: false; rejection: SnapshotRejection };

/** Parse the outer envelope and inner payload, without touching the signature. */
function parseSnapshotFile(text: string): SnapshotFile | undefined {
  let outer: unknown;
  try {
    outer = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (
    typeof outer !== "object" ||
    outer === null ||
    !("payload_json" in outer) ||
    typeof (outer as { payload_json: unknown }).payload_json !== "string"
  ) {
    return undefined;
  }
  const signature = (outer as { signature_b64?: unknown }).signature_b64;
  if (signature !== null && typeof signature !== "string") {
    return undefined;
  }
  return {
    payload_json: (outer as { payload_json: string }).payload_json,
    signature_b64: signature ?? null,
  };
}

function parsePayload(payloadJson: string): SnapshotPayload | undefined {
  let value: unknown;
  try {
    value = JSON.parse(payloadJson);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null) return undefined;
  const p = value as Record<string, unknown>;
  if (
    typeof p["generated_at"] !== "number" ||
    !Array.isArray(p["hosts"]) ||
    !Array.isArray(p["users"]) ||
    !Array.isArray(p["roles"]) ||
    !Array.isArray(p["tags"])
  ) {
    return undefined;
  }
  return {
    generated_at: p["generated_at"],
    hosts: p["hosts"] as SnapshotHost[],
    users: p["users"] as string[],
    roles: p["roles"] as string[],
    tags: p["tags"] as SnapshotTag[],
  };
}

/** Decode standard, padded Base64 into bytes. */
function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Verify `payloadJson`'s ECDSA P-256/SHA-256 signature against `verifyKeyJwk`.
 * Injected as a parameter (rather than hard-wired to `crypto.subtle`) so
 * {@link acceptSnapshot} stays a pure decision function; the production
 * caller passes {@link webCryptoVerifier}.
 */
export type SignatureVerifier = (
  payloadJson: string,
  signatureB64: string,
  verifyKeyJwk: JsonWebKey,
) => Promise<boolean>;

/** The real verifier, backed by WebCrypto (available in every target browser and in Node's `node:test`). */
export const webCryptoVerifier: SignatureVerifier = async (payloadJson, signatureB64, jwk) => {
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const data = new TextEncoder().encode(payloadJson);
  const signature = b64ToBytes(signatureB64);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
};

/**
 * Decide whether `text` is an acceptable snapshot, per the spec's two
 * scenarios: a signed snapshot with a bad (or unverifiable, for lack of a
 * configured key) signature is rejected outright — forms are not filled from
 * it; an unsigned snapshot is always accepted and labelled `manual`.
 */
export async function acceptSnapshot(
  text: string,
  verifyKeyJwk: JsonWebKey | undefined,
  now: number,
  verify: SignatureVerifier = webCryptoVerifier,
): Promise<SnapshotResult> {
  const file = parseSnapshotFile(text);
  if (!file) {
    return { ok: false, rejection: { kind: "malformed", message: "not a snapshot file" } };
  }
  const payload = parsePayload(file.payload_json);
  if (!payload) {
    return {
      ok: false,
      rejection: { kind: "malformed", message: "snapshot payload is malformed" },
    };
  }

  if (file.signature_b64 === null) {
    return {
      ok: true,
      snapshot: { origin: "manual", payload, ageSeconds: Math.max(0, now - payload.generated_at) },
    };
  }

  if (!verifyKeyJwk) {
    return { ok: false, rejection: { kind: "no_key" } };
  }

  let valid: boolean;
  try {
    valid = await verify(file.payload_json, file.signature_b64, verifyKeyJwk);
  } catch {
    valid = false;
  }
  if (!valid) {
    return { ok: false, rejection: { kind: "bad_signature" } };
  }
  return {
    ok: true,
    snapshot: { origin: "signed", payload, ageSeconds: Math.max(0, now - payload.generated_at) },
  };
}
