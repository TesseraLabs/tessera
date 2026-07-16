// Form-side envelope handling (spec `issuer-cabinet` — "Предъявлен CA
// организации": forms are restricted to the parent envelope, values outside
// it are not offered and are rejected). This module is the pure logic behind
// that: it never reaches into the DOM or the WASM core, so it is directly
// unit-testable.
//
// The WASM core (`build_leaf_tbs`/`build_ca_tbs`) is the authority — it runs
// the same monotonicity predicate the Engine enforces and is the last word.
// This module exists so the *form* never offers a value that core would
// reject, giving the operator the "already scoped" experience the spec
// requires ("значения вне рамок не предлагаются и отвергаются") rather than
// a client-side simulation of the check.

import type { EnvelopeJson } from "../types.ts";

/** One delegation-envelope dimension, matching the WASM `ApiError.dimension`. */
export type EnvelopeDimension = "require_tags" | "allow_roles" | "max_level" | "max_ttl";

/** A field selection outside the parent envelope, with the offending dimension. */
export interface EnvelopeViolation {
  dimension: EnvelopeDimension;
  message: string;
}

/**
 * The roles selectable for a leaf or child CA under `parent` — exactly the
 * parent's `allow_roles`. There is no "select all" escape hatch: a role not
 * in this list must not appear in a select/checkbox list built from it.
 */
export function selectableRoles(parent: EnvelopeJson): string[] {
  return [...parent.allow_roles];
}

/**
 * The roles a leaf form actually offers when an inventory is on hand (spec
 * `issuer-cabinet` — "Инвентарь для форм"): the intersection of the parent
 * envelope's roles with the inventory's roles, in the envelope's order — the
 * envelope stays the ceiling, the inventory only narrows and suggests. A role
 * present in the inventory but outside the envelope is silently dropped (it
 * was never selectable in the first place).
 *
 * An inventory that doesn't list any roles at all — `snapshotRoles`
 * `undefined` *or* an empty array — does not narrow anything: it's read as
 * "this inventory has no opinion on roles" (an operator who built an
 * inventory purely for the host/user suggestions, without filling in roles,
 * must not end up with zero roles offered — a snapshot with no roles is not
 * the same claim as a snapshot that positively lists none). Narrowing, and
 * the form's "narrowed by inventory" note, only kick in once the inventory
 * actually names at least one role.
 */
export function rolesForSelection(envelopeRoles: string[], snapshotRoles?: string[]): string[] {
  if (snapshotRoles === undefined || snapshotRoles.length === 0) return [...envelopeRoles];
  const inInventory = new Set(snapshotRoles);
  return envelopeRoles.filter((role) => inInventory.has(role));
}

/** The largest integrity level a form may offer under `parent`. */
export function maxSelectableLevel(parent: EnvelopeJson): number {
  return parent.max_level;
}

/** The largest TTL (seconds) a form may offer under `parent`. */
export function maxSelectableTtl(parent: EnvelopeJson): number {
  return parent.max_ttl;
}

/**
 * Validate a leaf's requested `allowed_roles` and (optional) integrity level
 * against `parent`, returning every violated dimension — empty when the
 * selection is entirely inside the envelope. Mirrors the subset of the
 * core's `narrows`/leaf self-check that a leaf form can pre-empt (roles,
 * integrity level); `require_tags`/`max_ttl` on a leaf are enforced by the
 * core's validity/host-binding checks, not by leaf role selection, so they
 * are validated only for a child-CA envelope (see {@link validateChildEnvelope}).
 */
export function validateLeafSelection(
  parent: EnvelopeJson,
  selection: { allowedRoles: string[]; maxIntegrityLevel?: number },
): EnvelopeViolation[] {
  const violations: EnvelopeViolation[] = [];
  for (const role of selection.allowedRoles) {
    if (!parent.allow_roles.includes(role)) {
      violations.push({
        dimension: "allow_roles",
        message: `role "${role}" is not in the parent envelope`,
      });
    }
  }
  if (
    selection.maxIntegrityLevel !== undefined &&
    selection.maxIntegrityLevel > parent.max_level
  ) {
    violations.push({
      dimension: "max_level",
      message: `integrity level ${selection.maxIntegrityLevel} exceeds parent ceiling ${parent.max_level}`,
    });
  }
  return violations;
}

/**
 * Validate a child CA's proposed envelope against its `parent`'s — the
 * monotone-narrowing predicate (`tessera_ext::delegation::narrows`) mirrored
 * client-side across all four dimensions, so the CA form rejects a widening
 * before the operator ever reaches the signing step.
 */
export function validateChildEnvelope(
  parent: EnvelopeJson,
  child: EnvelopeJson,
): EnvelopeViolation[] {
  const violations: EnvelopeViolation[] = [];

  for (const role of child.allow_roles) {
    if (!parent.allow_roles.includes(role)) {
      violations.push({
        dimension: "allow_roles",
        message: `role "${role}" is not in the parent envelope`,
      });
      break;
    }
  }

  if (child.max_level > parent.max_level) {
    violations.push({
      dimension: "max_level",
      message: `max_level ${child.max_level} exceeds parent ceiling ${parent.max_level}`,
    });
  }

  if (child.max_ttl > parent.max_ttl) {
    violations.push({
      dimension: "max_ttl",
      message: `max_ttl ${child.max_ttl} exceeds parent ceiling ${parent.max_ttl}`,
    });
  }

  // A child must require every tag the parent requires (narrowing may only
  // *add* required tags, never drop one): child.require_tags ⊇
  // parent.require_tags, exactly `narrows` in tessera_ext::delegation.
  for (const [key, parentValue] of parent.require_tags) {
    const inherited = child.require_tags.some(
      ([childKey, childValue]) => childKey === key && childValue === parentValue,
    );
    if (!inherited) {
      violations.push({
        dimension: "require_tags",
        message: `required tag "${key}=${parentValue}" is missing from the child envelope`,
      });
      break;
    }
  }

  return violations;
}
