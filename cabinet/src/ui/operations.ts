// Pure logic for which issuance operations a loaded parent certificate makes
// available (design note, `cabinet-operation-choice`): the WASM core
// (`buildCaTbs`/`buildLeafTbs`) accepts either operation from any CA parent
// that carries a delegation envelope — root or organisation CA alike — so the
// UI must offer a choice rather than hard-wiring one operation per `kind`.
// Kept separate from `app.ts` so the availability/default rules are
// unit-testable without a DOM (see `operations.test.ts`).

import type { ParentKind } from "../types.ts";

/** The two envelope-scoped issuance operations `app.ts` can render a form for (CRL is not scoped by envelope and is handled separately). */
export type IssuanceOperation = "ca" | "leaf";

/**
 * The issuance operations available for a parent of the given `kind` with
 * (or without) a delegation envelope. Only `root` and `org_ca` parents that
 * carry an envelope can issue anything; a `leaf` or `unusable` parent (or a
 * CA parent whose envelope failed to parse) offers none.
 */
export function availableIssuanceOperations(
  kind: ParentKind,
  hasEnvelope: boolean,
): IssuanceOperation[] {
  if (!hasEnvelope) return [];
  if (kind === "root" || kind === "org_ca") return ["ca", "leaf"];
  return [];
}

/**
 * The operation pre-selected when a parent of the given `kind` is loaded —
 * preserves the cabinet's previous, kind-specific default (root → CA
 * organisation, organisation CA → shift leaf) even though both are now also
 * reachable via the switch.
 */
export function defaultIssuanceOperation(kind: ParentKind): IssuanceOperation {
  return kind === "org_ca" ? "leaf" : "ca";
}
