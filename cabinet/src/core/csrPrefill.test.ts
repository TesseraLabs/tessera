import test from "node:test";
import assert from "node:assert/strict";

import { computeLeafPrefill } from "./csrPrefill.ts";
import type { EnvelopeJson } from "../types.ts";

const parent: EnvelopeJson = {
  require_tags: [],
  allow_roles: ["oper", "serv"],
  max_level: 3,
  max_ttl: 3600,
};

test("host/user binding and profile_version prefill unconditionally (not envelope-scoped)", () => {
  const prefill = computeLeafPrefill(parent, {
    host_binding: ["sha256:aaaa"],
    user_binding: ["ivanov"],
    profile_version: 2,
  });
  assert.deepEqual(prefill.hostBinding, ["sha256:aaaa"]);
  assert.deepEqual(prefill.userBinding, ["ivanov"]);
  assert.equal(prefill.profileVersion, 2);
  assert.deepEqual(prefill.rejectedRoles, []);
});

test("allowed_roles inside the envelope prefill; roles outside are reported, not applied", () => {
  const prefill = computeLeafPrefill(parent, { allowed_roles: ["oper", "admin"] });
  assert.deepEqual(prefill.allowedRoles, ["oper"]);
  assert.deepEqual(prefill.rejectedRoles, ["admin"]);
});

test("max_integrity within the ceiling prefills level and categories together", () => {
  const prefill = computeLeafPrefill(parent, { max_integrity: { level: 2, categories: 5 } });
  assert.equal(prefill.maxIntegrityLevel, 2);
  assert.equal(prefill.maxIntegrityCategories, 5);
  assert.equal(prefill.rejectedIntegrityLevel, undefined);
});

test("max_integrity above the ceiling is rejected, not applied", () => {
  const prefill = computeLeafPrefill(parent, { max_integrity: { level: 5, categories: 1 } });
  assert.equal(prefill.maxIntegrityLevel, undefined);
  assert.equal(prefill.maxIntegrityCategories, undefined);
  assert.equal(prefill.rejectedIntegrityLevel, 5);
});

test("an integrity level exactly at the ceiling is accepted (ceiling is inclusive)", () => {
  const prefill = computeLeafPrefill(parent, { max_integrity: { level: 3, categories: 0 } });
  assert.equal(prefill.maxIntegrityLevel, 3);
});

test("an empty/absent requested_parsed prefills nothing", () => {
  const prefill = computeLeafPrefill(parent, {});
  assert.deepEqual(prefill, { rejectedRoles: [] });
});

test("all roles rejected leaves allowedRoles unset but reports every rejection", () => {
  const prefill = computeLeafPrefill(parent, { allowed_roles: ["admin", "root"] });
  assert.equal(prefill.allowedRoles, undefined);
  assert.deepEqual(prefill.rejectedRoles, ["admin", "root"]);
});
