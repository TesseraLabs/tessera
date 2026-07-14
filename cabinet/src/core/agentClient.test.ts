import test from "node:test";
import assert from "node:assert/strict";

import { agentAlgorithmToWasmTag } from "./agentClient.ts";

test("agentAlgorithmToWasmTag maps every agent wire tag to a WASM tag", () => {
  assert.equal(agentAlgorithmToWasmTag("ecdsa-with-sha256"), "ecdsa-p256");
  assert.equal(agentAlgorithmToWasmTag("ecdsa-with-sha384"), "ecdsa-p384");
  assert.equal(agentAlgorithmToWasmTag("rsa-pkcs1-sha256"), "rsa-sha256");
  assert.equal(agentAlgorithmToWasmTag("ed25519"), "ed25519");
});
