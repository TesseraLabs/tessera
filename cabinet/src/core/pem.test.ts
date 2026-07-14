import test from "node:test";
import assert from "node:assert/strict";

import { pemOrDer } from "./pem.ts";

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

test("pemOrDer passes DER through unchanged", () => {
  const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);
  assert.deepEqual(pemOrDer(der), der);
});

test("pemOrDer decodes a PEM wrapper to the same DER bytes", () => {
  const der = crypto.getRandomValues(new Uint8Array(300));
  const b64 = bytesToB64(der);
  const lines = b64.match(/.{1,64}/g) ?? [];
  const pem = `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
  const decoded = pemOrDer(new TextEncoder().encode(pem));
  assert.deepEqual(decoded, der);
});

test("pemOrDer tolerates leading whitespace before the PEM header", () => {
  const pem = "\n\n  -----BEGIN X-----\nQQ==\n-----END X-----\n";
  const decoded = pemOrDer(new TextEncoder().encode(pem));
  assert.deepEqual(decoded, new Uint8Array([0x41]));
});

test("pemOrDer throws on an empty PEM body", () => {
  const pem = "-----BEGIN X-----\n-----END X-----\n";
  assert.throws(() => pemOrDer(new TextEncoder().encode(pem)));
});
