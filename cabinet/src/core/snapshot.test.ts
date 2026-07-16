import test from "node:test";
import assert from "node:assert/strict";

import { acceptSnapshot, buildManualSnapshot } from "./snapshot.ts";
import type { SnapshotPayload } from "./snapshot.ts";

const payload = {
  generated_at: 1_750_000_000,
  hosts: [{ id: "sha256:aaaa", label: "north-01" }],
  users: ["ivanov"],
  roles: ["oper"],
  tags: [{ key: "region", value: "north" }],
};
const payloadJson = JSON.stringify(payload);

function bytesToB64(bytes: ArrayBuffer): string {
  return Buffer.from(bytes).toString("base64");
}

async function signPayload(): Promise<{ jwk: JsonWebKey; signatureB64: string }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    new TextEncoder().encode(payloadJson),
  );
  return { jwk, signatureB64: bytesToB64(signature) };
}

test("a validly signed snapshot is accepted and labelled signed", async () => {
  const { jwk, signatureB64 } = await signPayload();
  const file = JSON.stringify({ payload_json: payloadJson, signature_b64: signatureB64 });

  const result = await acceptSnapshot(file, jwk, 1_750_003_600);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.snapshot.origin, "signed");
    assert.equal(result.snapshot.ageSeconds, 3600);
    assert.deepEqual(result.snapshot.payload.roles, ["oper"]);
  }
});

test("a snapshot with an invalid signature is rejected, not filled", async () => {
  const { jwk } = await signPayload();
  const bogusSignature = Buffer.alloc(64, 7).toString("base64");
  const file = JSON.stringify({ payload_json: payloadJson, signature_b64: bogusSignature });

  const result = await acceptSnapshot(file, jwk, 1_750_003_600);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.rejection.kind, "bad_signature");
  }
});

test("a signature over tampered payload text is rejected", async () => {
  const { jwk, signatureB64 } = await signPayload();
  const tampered = JSON.stringify({ ...payload, roles: ["oper", "admin"] });
  const file = JSON.stringify({ payload_json: tampered, signature_b64: signatureB64 });

  const result = await acceptSnapshot(file, jwk, 1_750_003_600);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.rejection.kind, "bad_signature");
  }
});

test("a signed snapshot with no configured verification key is rejected", async () => {
  const { signatureB64 } = await signPayload();
  const file = JSON.stringify({ payload_json: payloadJson, signature_b64: signatureB64 });

  const result = await acceptSnapshot(file, undefined, 1_750_003_600);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.rejection.kind, "no_key");
  }
});

test("an unsigned snapshot is always accepted and labelled manual", async () => {
  const file = JSON.stringify({ payload_json: payloadJson, signature_b64: null });

  const result = await acceptSnapshot(file, undefined, 1_750_003_600);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.snapshot.origin, "manual");
  }
});

test("malformed snapshot files are rejected", async () => {
  const notJson = await acceptSnapshot("not json", undefined, 0);
  assert.equal(notJson.ok, false);

  const missingPayload = await acceptSnapshot(
    JSON.stringify({ signature_b64: null }),
    undefined,
    0,
  );
  assert.equal(missingPayload.ok, false);

  const badPayload = await acceptSnapshot(
    JSON.stringify({ payload_json: "{}", signature_b64: null }),
    undefined,
    0,
  );
  assert.equal(badPayload.ok, false);
});

test("buildManualSnapshot round-trips through acceptSnapshot as a manual snapshot", async () => {
  const constructed: SnapshotPayload = {
    generated_at: 1_750_000_000,
    hosts: [{ id: "sha256:bbbb", label: "south-02" }],
    users: ["petrov"],
    roles: ["oper", "serv"],
    tags: [{ key: "region", value: "south" }],
  };
  const file = buildManualSnapshot(constructed);
  assert.equal(file.signature_b64, null);

  const result = await acceptSnapshot(JSON.stringify(file), undefined, 1_750_000_900);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.snapshot.origin, "manual");
    assert.equal(result.snapshot.ageSeconds, 900);
    assert.deepEqual(result.snapshot.payload, constructed);
  }
});
