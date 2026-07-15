import test from "node:test";
import assert from "node:assert/strict";

import {
  agentAlgorithmToWasmTag,
  agentInfo,
  agentSign,
  AgentError,
  isLoopbackAgentAddress,
} from "./agentClient.ts";

test("agentAlgorithmToWasmTag maps every agent wire tag to a WASM tag", () => {
  assert.equal(agentAlgorithmToWasmTag("ecdsa-with-sha256"), "ecdsa-p256");
  assert.equal(agentAlgorithmToWasmTag("ecdsa-with-sha384"), "ecdsa-p384");
  assert.equal(agentAlgorithmToWasmTag("rsa-pkcs1-sha256"), "rsa-sha256");
  assert.equal(agentAlgorithmToWasmTag("ed25519"), "ed25519");
});

test("isLoopbackAgentAddress accepts http(s) 127.0.0.1/::1/localhost with any port", () => {
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1:38217"), true);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1"), true);
  assert.equal(isLoopbackAgentAddress("http://localhost:8080"), true);
  assert.equal(isLoopbackAgentAddress("HTTP://LOCALHOST:8080"), true);
  assert.equal(isLoopbackAgentAddress("https://127.0.0.1:8443"), true);
  assert.equal(isLoopbackAgentAddress("http://[::1]:9000"), true);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1:38217/"), true);
});

test("isLoopbackAgentAddress rejects non-loopback hosts", () => {
  assert.equal(isLoopbackAgentAddress("https://evil.example"), false);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1.evil.example"), false);
  assert.equal(isLoopbackAgentAddress("http://0.0.0.0:8080"), false);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.2:8080"), false);
  assert.equal(isLoopbackAgentAddress("http://169.254.1.1:8080"), false);
});

test("isLoopbackAgentAddress rejects non-http(s) schemes, paths, and malformed input", () => {
  assert.equal(isLoopbackAgentAddress("file:///etc/passwd"), false);
  assert.equal(isLoopbackAgentAddress("javascript:alert(1)"), false);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1:8080/sign"), false);
  assert.equal(isLoopbackAgentAddress("http://127.0.0.1:8080?x=1"), false);
  assert.equal(isLoopbackAgentAddress("not a url"), false);
  assert.equal(isLoopbackAgentAddress(""), false);
});

test("agentInfo rejects a non-loopback address before any fetch", async () => {
  await assert.rejects(() => agentInfo("https://evil.example", "token"), AgentError);
});

test("agentSign rejects a non-loopback address before any fetch", async () => {
  await assert.rejects(() => agentSign("https://evil.example", "token", "key", "dGJz"), AgentError);
});
