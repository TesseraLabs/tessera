// Turns `inspect_csr`'s `requested_parsed` into leaf-form prefill (spec
// `issuer-cabinet` — "Источник ключа листа — SPKI или CSR": prefill "ДОЛЖНО
// (MUST) быть явно помечено как «запрошено в CSR» и редактируемо").
//
// The envelope-scoped fields (`allowed_roles`, `max_integrity`) are filtered
// here so the form never prefills a value the parent envelope would reject —
// a role or integrity level the CSR requested but the envelope excludes is
// silently dropped (not offered, not auto-selected), which the UI reports as
// "requested, but out of scope" per the team-lead's brief, not silently
// accepted. `host_binding`/`user_binding`/`profile_version` are not
// envelope-scoped dimensions (see `core/envelope.ts`), so they prefill
// unconditionally when the CSR requested them.

import type { EnvelopeJson, RequestedParsedJson } from "../types.ts";

export interface LeafPrefill {
  hostBinding?: string[];
  userBinding?: string[];
  allowedRoles?: string[];
  maxIntegrityLevel?: number;
  maxIntegrityCategories?: number;
  profileVersion?: number;
  /** Roles the CSR requested but the parent envelope does not allow — reported, not applied. */
  rejectedRoles: string[];
  /** The CSR's requested integrity level, when it exceeded the parent's ceiling — reported, not applied. */
  rejectedIntegrityLevel?: number;
}

export function computeLeafPrefill(parent: EnvelopeJson, parsed: RequestedParsedJson): LeafPrefill {
  const prefill: LeafPrefill = { rejectedRoles: [] };

  if (parsed.host_binding && parsed.host_binding.length > 0) {
    prefill.hostBinding = parsed.host_binding;
  }
  if (parsed.user_binding && parsed.user_binding.length > 0) {
    prefill.userBinding = parsed.user_binding;
  }
  if (parsed.profile_version !== undefined) {
    prefill.profileVersion = parsed.profile_version;
  }

  if (parsed.allowed_roles && parsed.allowed_roles.length > 0) {
    const allowed: string[] = [];
    const rejected: string[] = [];
    for (const role of parsed.allowed_roles) {
      (parent.allow_roles.includes(role) ? allowed : rejected).push(role);
    }
    if (allowed.length > 0) prefill.allowedRoles = allowed;
    prefill.rejectedRoles = rejected;
  }

  if (parsed.max_integrity) {
    if (parsed.max_integrity.level <= parent.max_level) {
      prefill.maxIntegrityLevel = parsed.max_integrity.level;
      prefill.maxIntegrityCategories = parsed.max_integrity.categories;
    } else {
      prefill.rejectedIntegrityLevel = parsed.max_integrity.level;
    }
  }

  return prefill;
}
