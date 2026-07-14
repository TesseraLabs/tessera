import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { sha256HexOfDer } from "./fingerprint.ts";

test("sha256HexOfDer matches Node's own SHA-256 hex digest", async () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const expected = createHash("sha256").update(bytes).digest("hex");
  assert.equal(await sha256HexOfDer(bytes), expected);
});

test("sha256HexOfDer is deterministic and content-sensitive", async () => {
  const a = await sha256HexOfDer(new Uint8Array([1, 2, 3]));
  const b = await sha256HexOfDer(new Uint8Array([1, 2, 3]));
  const c = await sha256HexOfDer(new Uint8Array([1, 2, 4]));
  assert.equal(a, b);
  assert.notEqual(a, c);
});
