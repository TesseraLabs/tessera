import test from "node:test";
import assert from "node:assert/strict";

import { availableIssuanceOperations, defaultIssuanceOperation } from "./operations.ts";

test("availableIssuanceOperations offers both operations for a root with an envelope", () => {
  assert.deepEqual(availableIssuanceOperations("root", true), ["ca", "leaf"]);
});

test("availableIssuanceOperations offers both operations for an org_ca with an envelope", () => {
  assert.deepEqual(availableIssuanceOperations("org_ca", true), ["ca", "leaf"]);
});

test("availableIssuanceOperations offers nothing without an envelope, regardless of kind", () => {
  assert.deepEqual(availableIssuanceOperations("root", false), []);
  assert.deepEqual(availableIssuanceOperations("org_ca", false), []);
});

test("availableIssuanceOperations offers nothing for a leaf or unusable parent", () => {
  assert.deepEqual(availableIssuanceOperations("leaf", true), []);
  assert.deepEqual(availableIssuanceOperations("unusable", true), []);
});

test("defaultIssuanceOperation: root defaults to CA, org_ca defaults to leaf", () => {
  assert.equal(defaultIssuanceOperation("root"), "ca");
  assert.equal(defaultIssuanceOperation("org_ca"), "leaf");
});

test("defaultIssuanceOperation: leaf/unusable default to CA (never rendered, but total for callers)", () => {
  assert.equal(defaultIssuanceOperation("leaf"), "ca");
  assert.equal(defaultIssuanceOperation("unusable"), "ca");
});
