/* tslint:disable */
/* eslint-disable */

/**
 * Assemble the final artifact from a signed `TBS` and self-check it against the
 * parent envelope; return `{ cert_pem, cert_b64, kind }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input, a signature algorithm that
 * disagrees with the `TBS`, or a failed self-check (a scope violation names the
 * `dimension`).
 */
export function assemble_and_verify(input: string): string;

/**
 * Build the `TBSCertificate` for an organisation CA and return
 * `{ tbs_b64, summary }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input or a widened envelope (naming the
 * `dimension`).
 */
export function build_ca_tbs(input: string): string;

/**
 * Build the `TBSCertList` for a CRL and return `{ tbs_b64, summary }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input or a non-monotone `crlNumber`.
 */
export function build_crl_tbs(input: string): string;

/**
 * Build the `TBSCertificate` for an engineer shift-leaf, running every core
 * check, and return `{ tbs_b64, summary }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input or any core rejection (a widened
 * envelope names the `dimension`; a bad CSR fails proof of possession).
 */
export function build_leaf_tbs(input: string): string;

/**
 * Inspect a CSR: return `{ subject, signature_valid, spki_b64,
 * requested_extensions }` for the CSR key-source path.
 *
 * # Errors
 *
 * A JSON `error` string when the CSR does not parse.
 */
export function inspect_csr(input: string): string;

/**
 * Classify a parent certificate to derive the cabinet's available operations.
 *
 * Input `{ cert_b64 }`; output `{ kind, subject, envelope?, reason? }` where
 * `kind` is `root` (issue org CAs), `org_ca` (issue leaves), `leaf`, or
 * `unusable`.
 *
 * # Errors
 *
 * A JSON [`error`](crate) string on malformed input.
 */
export function inspect_parent(input: string): string;

/**
 * Append one issuance entry to the hash-chained journal and return
 * `{ new_line }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input or a storage failure.
 */
export function journal_append(input: string): string;

/**
 * Verify the journal's hash chain and return `{ status, position?,
 * unsigned_from_seq?, entry_count, last_signed_seq? }`.
 *
 * # Errors
 *
 * A JSON `error` string on malformed input.
 */
export function journal_verify(input: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly assemble_and_verify: (a: number, b: number, c: number) => void;
    readonly build_ca_tbs: (a: number, b: number, c: number) => void;
    readonly build_crl_tbs: (a: number, b: number, c: number) => void;
    readonly build_leaf_tbs: (a: number, b: number, c: number) => void;
    readonly inspect_csr: (a: number, b: number, c: number) => void;
    readonly inspect_parent: (a: number, b: number, c: number) => void;
    readonly journal_append: (a: number, b: number, c: number) => void;
    readonly journal_verify: (a: number, b: number, c: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
