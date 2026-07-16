import test from "node:test";
import assert from "node:assert/strict";

import {
  maxSelectableLevel,
  maxSelectableTtl,
  rolesForSelection,
  selectableRoles,
  validateChildEnvelope,
  validateLeafSelection,
} from "./envelope.ts";
import type { EnvelopeJson } from "../types.ts";

const parent: EnvelopeJson = {
  require_tags: [["region", "north"]],
  allow_roles: ["oper", "serv"],
  max_level: 5,
  max_ttl: 14400,
};

test("selectableRoles/maxSelectable* mirror the parent envelope exactly", () => {
  assert.deepEqual(selectableRoles(parent), ["oper", "serv"]);
  assert.equal(maxSelectableLevel(parent), 5);
  assert.equal(maxSelectableTtl(parent), 14400);
});

test("validateLeafSelection accepts a selection fully inside the envelope", () => {
  const violations = validateLeafSelection(parent, {
    allowedRoles: ["oper"],
    maxIntegrityLevel: 2,
  });
  assert.deepEqual(violations, []);
});

test("validateLeafSelection flags a role outside allow_roles", () => {
  const violations = validateLeafSelection(parent, {
    allowedRoles: ["oper", "admin"],
  });
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.dimension, "allow_roles");
});

test("validateLeafSelection flags an integrity level above the ceiling", () => {
  const violations = validateLeafSelection(parent, {
    allowedRoles: [],
    maxIntegrityLevel: 6,
  });
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.dimension, "max_level");
});

test("validateChildEnvelope accepts a proper narrowing", () => {
  const child: EnvelopeJson = {
    require_tags: [
      ["region", "north"],
      ["site", "msk-1"],
    ],
    allow_roles: ["oper"],
    max_level: 3,
    max_ttl: 3600,
  };
  assert.deepEqual(validateChildEnvelope(parent, child), []);
});

test("validateChildEnvelope rejects a role the parent does not allow", () => {
  const child: EnvelopeJson = { ...parent, allow_roles: ["oper", "root"] };
  const violations = validateChildEnvelope(parent, child);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.dimension, "allow_roles");
});

test("validateChildEnvelope rejects max_level/max_ttl above the parent ceiling", () => {
  const child: EnvelopeJson = { ...parent, max_level: 6, max_ttl: 20000 };
  const violations = validateChildEnvelope(parent, child);
  const dims = violations.map((v) => v.dimension).sort();
  assert.deepEqual(dims, ["max_level", "max_ttl"]);
});

test("validateChildEnvelope rejects a dropped or altered required tag", () => {
  const dropped: EnvelopeJson = { ...parent, require_tags: [] };
  assert.equal(validateChildEnvelope(parent, dropped)[0]?.dimension, "require_tags");

  const altered: EnvelopeJson = { ...parent, require_tags: [["region", "south"]] };
  assert.equal(validateChildEnvelope(parent, altered)[0]?.dimension, "require_tags");
});

test("validateChildEnvelope accepts equality (same envelope, not narrowed further)", () => {
  assert.deepEqual(validateChildEnvelope(parent, { ...parent }), []);
});

test("rolesForSelection without an inventory returns the envelope's roles as-is, in order", () => {
  assert.deepEqual(rolesForSelection(selectableRoles(parent)), ["oper", "serv"]);
});

test("rolesForSelection with an inventory returns the intersection, ordered by the envelope", () => {
  assert.deepEqual(rolesForSelection(["oper", "serv"], ["serv", "oper"]), ["oper", "serv"]);
});

test("rolesForSelection drops an inventory role outside the envelope", () => {
  assert.deepEqual(rolesForSelection(["oper", "serv"], ["oper", "admin"]), ["oper"]);
});

test("rolesForSelection with an inventory that lists no roles does not narrow — full envelope offered", () => {
  assert.deepEqual(rolesForSelection(["oper", "serv"], []), ["oper", "serv"]);
});
