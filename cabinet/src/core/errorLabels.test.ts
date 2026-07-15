import test from "node:test";
import assert from "node:assert/strict";

import { parseApiError, renderApiError } from "./errorLabels.ts";

test("renderApiError appends the localized dimension caption", () => {
  const err = { error: "allowed role `admin` is not in the parent envelope", dimension: "allow_roles" };
  assert.equal(
    renderApiError("en", err),
    "allowed role `admin` is not in the parent envelope (allowed roles)",
  );
  assert.equal(
    renderApiError("ru", err),
    "allowed role `admin` is not in the parent envelope (допустимые роли)",
  );
});

test("renderApiError returns the bare message when there is no dimension", () => {
  assert.equal(renderApiError("en", { error: "invalid base64" }), "invalid base64");
});

test("renderApiError falls back to the raw dimension key for an unknown dimension", () => {
  assert.equal(
    renderApiError("en", { error: "x", dimension: "something_new" }),
    "x (something_new)",
  );
});

test("parseApiError parses the thrown JSON string", () => {
  const thrown = JSON.stringify({ error: "boom", dimension: "max_ttl" });
  assert.deepEqual(parseApiError(thrown), { error: "boom", dimension: "max_ttl" });
});

test("parseApiError handles a message with no dimension field", () => {
  const thrown = JSON.stringify({ error: "boom" });
  assert.deepEqual(parseApiError(thrown), { error: "boom" });
});

test("parseApiError falls back gracefully on non-JSON or non-string throws", () => {
  assert.deepEqual(parseApiError("not json"), { error: "not json" });
  assert.deepEqual(parseApiError(new Error("oops")), { error: "Error: oops" });
});
