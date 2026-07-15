// Shared TypeScript shapes mirroring the WASM binding JSON contracts
// (crates/tessera_issuer_wasm/src/types.rs) and the `issuer serve` HTTP
// protocol (crates/tessera_issuer/src/serve.rs). Kept as one file so a
// contract change in either surface is a one-file diff here.

/** A delegation envelope, mirrored from the core's `DelegationConstraints`. */
export interface EnvelopeJson {
  require_tags: [string, string][];
  allow_roles: string[];
  max_level: number;
  max_ttl: number;
}

export type ParentKind = "root" | "org_ca" | "leaf" | "unusable";

export interface InspectParentResponse {
  kind: ParentKind;
  subject: string;
  envelope?: EnvelopeJson;
  reason?: string;
}

export interface ValidityJson {
  not_before: number;
  not_after: number;
}

export interface IntegrityJson {
  level: number;
  categories: number;
}

export interface LeafRequestJson {
  subject?: string;
  spki_b64?: string;
  csr_b64?: string;
  validity: ValidityJson;
  host_binding: string[];
  user_binding: string[];
  allowed_roles: string[];
  max_integrity?: IntegrityJson;
  profile_version: number;
}

export interface BuildLeafInput {
  parent_b64: string;
  algorithm: SignatureAlgorithmTag;
  serial_entropy_b64: string;
  locale?: string;
  request: LeafRequestJson;
}

export interface CaRequestJson {
  subject: string;
  spki_b64: string;
  validity: ValidityJson;
  constraints: EnvelopeJson;
  profile_version: number;
}

export interface BuildCaInput {
  parent_b64: string;
  algorithm: SignatureAlgorithmTag;
  serial_entropy_b64: string;
  locale?: string;
  request: CaRequestJson;
}

export interface RevokedJson {
  serial_b64: string;
  revocation_date: number;
  reason?: number;
}

export interface CrlRequestJson {
  this_update: number;
  next_update?: number;
  crl_number: number;
  revoked: RevokedJson[];
}

export interface BuildCrlInput {
  issuer_b64: string;
  algorithm: SignatureAlgorithmTag;
  locale?: string;
  request: CrlRequestJson;
  last_crl_number: number;
}

export interface SummaryLineJson {
  label: string;
  value: string;
}

export interface SummaryJson {
  kind: "shift_leaf" | "org_ca" | "crl";
  subject: string;
  not_before: string;
  not_after: string;
  lines: SummaryLineJson[];
  rendered: string;
}

export interface BuildTbsResponse {
  tbs_b64: string;
  summary: SummaryJson;
}

export interface InspectCsrInput {
  csr_b64: string;
}

export interface RequestedExtensionJson {
  oid: string;
  critical: boolean;
  value_b64: string;
}

export interface InspectCsrResponse {
  subject: string;
  signature_valid: boolean;
  spki_b64: string;
  requested_extensions: RequestedExtensionJson[];
  /**
   * The subset of requested extensions the core could parse into known leaf
   * scope fields — the object is always present, but each of its own
   * fields is present only when the CSR actually requested that extension
   * and the core recognised it (`crates/tessera_issuer_wasm/src/types.rs`,
   * `RequestedParsedJson`). `requested_extensions` above (the raw DER list)
   * is unaffected and always present regardless. See `core/csrPrefill.ts`
   * for how the cabinet turns this into form prefill.
   */
  requested_parsed: RequestedParsedJson;
}

export interface RequestedParsedJson {
  allowed_roles?: string[];
  host_binding?: string[];
  user_binding?: string[];
  max_integrity?: IntegrityJson;
  profile_version?: number;
}

export type SignatureAlgorithmTag =
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "rsa-sha256"
  | "ed25519";

export interface SignatureJson {
  algorithm: SignatureAlgorithmTag;
  bytes_b64: string;
}

export interface AssembleInput {
  tbs_b64: string;
  signature: SignatureJson;
  parent_b64: string;
}

export interface AssembleResponse {
  cert_pem: string;
  cert_b64: string;
  kind: "shift_leaf" | "org_ca" | "crl";
}

export type JournalEntryJson =
  | { op: "issue_leaf"; serial_b64: string; parent_b64: string; subject: string }
  | { op: "issue_ca"; serial_b64: string; parent_b64: string; subject: string }
  | { op: "issue_crl"; crl_number: number; parent_b64: string };

export interface JournalAppendInput {
  prev_lines: string[];
  entry: JournalEntryJson;
  now_unix: number;
}

export interface JournalAppendResponse {
  new_line: string;
}

export interface JournalVerifyInput {
  lines: string[];
}

export type JournalStatusTag = "intact" | "intact_unsigned_tail" | "broken" | "unknown";

export interface JournalVerifyResponse {
  status: JournalStatusTag;
  position?: number;
  unsigned_from_seq?: number;
  entry_count: number;
  last_signed_seq?: number;
}

/** The JSON error every WASM binding throws on failure. */
export interface ApiError {
  error: string;
  dimension?: string;
}

/** `POST /sign` request body accepted by `issuer serve`. */
export interface SignRequest {
  key_id: string;
  tbs_der_b64: string;
}

/**
 * The wire algorithm vocabulary `issuer serve` speaks (`algorithm_str` in
 * `crates/tessera_issuer/src/serve.rs`) — distinct from the
 * {@link SignatureAlgorithmTag} vocabulary the WASM bindings speak
 * (`parse_algorithm` in `crates/tessera_issuer_wasm/src/api.rs`). The two
 * never share a string, so `agentAlgorithmToWasmTag` in `agentClient.ts`
 * bridges them before `assemble_and_verify`.
 */
export type AgentAlgorithmTag =
  | "ecdsa-with-sha256"
  | "ecdsa-with-sha384"
  | "ed25519"
  | "rsa-pkcs1-sha256";

/** `POST /sign` success response from `issuer serve`. */
export interface SignResponse {
  signature_b64: string;
  algorithm: AgentAlgorithmTag;
}

/** `GET /info` response from `issuer serve`. */
export interface AgentInfoResponse {
  algorithms: AgentAlgorithmTag[];
  version: string;
}

/** `{"error": "..."}` body `issuer serve` returns on any rejection. */
export interface AgentErrorResponse {
  error: string;
}
