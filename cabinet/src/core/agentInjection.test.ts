import test from "node:test";
import assert from "node:assert/strict";

import { readAgentInjection } from "./agentInjection.ts";

test("returns agent settings from injected meta tags, address = origin", () => {
  const meta: Record<string, string> = {
    "tessera-agent-token": "paired-token-abc",
    "tessera-agent-key": "org-north-ca",
  };
  const result = readAgentInjection((name) => meta[name] ?? null, "http://127.0.0.1:38217");
  assert.deepEqual(result, {
    address: "http://127.0.0.1:38217",
    token: "paired-token-abc",
    keyId: "org-north-ca",
  });
});

test("returns undefined when the token meta tag is absent", () => {
  const meta: Record<string, string> = { "tessera-agent-key": "org-north-ca" };
  const result = readAgentInjection((name) => meta[name] ?? null, "http://127.0.0.1:38217");
  assert.equal(result, undefined);
});

test("returns undefined when the token meta tag is present but empty", () => {
  const meta: Record<string, string> = { "tessera-agent-token": "", "tessera-agent-key": "org-north-ca" };
  const result = readAgentInjection((name) => meta[name] ?? null, "http://127.0.0.1:38217");
  assert.equal(result, undefined);
});

test("keyId defaults to empty string when the key meta tag is absent", () => {
  const meta: Record<string, string> = { "tessera-agent-token": "paired-token-abc" };
  const result = readAgentInjection((name) => meta[name] ?? null, "http://127.0.0.1:38217");
  assert.deepEqual(result, {
    address: "http://127.0.0.1:38217",
    token: "paired-token-abc",
    keyId: "",
  });
});

test("keyId defaults to empty string when the key meta tag is present but empty", () => {
  const meta: Record<string, string> = { "tessera-agent-token": "paired-token-abc", "tessera-agent-key": "" };
  const result = readAgentInjection((name) => meta[name] ?? null, "http://127.0.0.1:38217");
  assert.deepEqual(result, {
    address: "http://127.0.0.1:38217",
    token: "paired-token-abc",
    keyId: "",
  });
});
