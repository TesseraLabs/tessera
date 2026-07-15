// Thin, typed wrapper over the generated `wasm-bindgen --target web`
// bindings (`../../wasm/tessera_issuer_wasm.js`, produced by `build.sh`
// step 2; see `wasmModule.d.ts` for the ambient contract this compiles
// against). Every function here does exactly one thing beyond the raw
// binding: `JSON.stringify` the typed request, call the binding, and
// `JSON.parse` the typed response — the error path is left to the caller
// (`parseApiError` in `errorLabels.ts`), since different call sites want to
// react to it differently (inline field errors vs. a toast).

import init, * as bindings from "../../wasm/tessera_issuer_wasm.js";

import type {
  AssembleInput,
  AssembleResponse,
  BuildCaInput,
  BuildCrlInput,
  BuildLeafInput,
  BuildTbsResponse,
  InspectCsrInput,
  InspectCsrResponse,
  InspectParentResponse,
  JournalAppendInput,
  JournalAppendResponse,
  JournalVerifyInput,
  JournalVerifyResponse,
} from "../types.ts";

let readyPromise: Promise<unknown> | undefined;

/** Initialise the WASM module once; safe to call from multiple call sites. */
export function ensureWasmReady(): Promise<unknown> {
  if (!readyPromise) {
    readyPromise = init();
  }
  return readyPromise;
}

export async function inspectParent(certB64: string): Promise<InspectParentResponse> {
  await ensureWasmReady();
  const raw = bindings.inspect_parent(JSON.stringify({ cert_b64: certB64 }));
  return JSON.parse(raw) as InspectParentResponse;
}

export async function buildLeafTbs(input: BuildLeafInput): Promise<BuildTbsResponse> {
  await ensureWasmReady();
  const raw = bindings.build_leaf_tbs(JSON.stringify(input));
  return JSON.parse(raw) as BuildTbsResponse;
}

export async function buildCaTbs(input: BuildCaInput): Promise<BuildTbsResponse> {
  await ensureWasmReady();
  const raw = bindings.build_ca_tbs(JSON.stringify(input));
  return JSON.parse(raw) as BuildTbsResponse;
}

export async function buildCrlTbs(input: BuildCrlInput): Promise<BuildTbsResponse> {
  await ensureWasmReady();
  const raw = bindings.build_crl_tbs(JSON.stringify(input));
  return JSON.parse(raw) as BuildTbsResponse;
}

export async function inspectCsr(csrB64: string): Promise<InspectCsrResponse> {
  await ensureWasmReady();
  const raw = bindings.inspect_csr(JSON.stringify({ csr_b64: csrB64 } satisfies InspectCsrInput));
  return JSON.parse(raw) as InspectCsrResponse;
}

export async function assembleAndVerify(input: AssembleInput): Promise<AssembleResponse> {
  await ensureWasmReady();
  const raw = bindings.assemble_and_verify(JSON.stringify(input));
  return JSON.parse(raw) as AssembleResponse;
}

export async function journalAppend(input: JournalAppendInput): Promise<JournalAppendResponse> {
  await ensureWasmReady();
  const raw = bindings.journal_append(JSON.stringify(input));
  return JSON.parse(raw) as JournalAppendResponse;
}

export async function journalVerify(lines: string[]): Promise<JournalVerifyResponse> {
  await ensureWasmReady();
  const raw = bindings.journal_verify(JSON.stringify({ lines } satisfies JournalVerifyInput));
  return JSON.parse(raw) as JournalVerifyResponse;
}

/** 16 bytes of CSPRNG entropy for a serial number, Base64-encoded. */
export function randomSerialEntropyB64(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
