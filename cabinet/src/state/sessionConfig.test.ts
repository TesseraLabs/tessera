import test from "node:test";
import assert from "node:assert/strict";

import {
  loadAgentSettings,
  loadExplicitLocale,
  loadSnapshotVerifyKey,
  saveAgentSettings,
  saveExplicitLocale,
  saveSnapshotVerifyKey,
} from "./sessionConfig.ts";

/** A minimal in-memory `Storage` for tests — Node has no `sessionStorage` global. */
class MapStorage implements Storage {
  #map = new Map<string, string>();
  get length(): number {
    return this.#map.size;
  }
  clear(): void {
    this.#map.clear();
  }
  getItem(key: string): string | null {
    return this.#map.get(key) ?? null;
  }
  key(index: number): string | null {
    return [...this.#map.keys()][index] ?? null;
  }
  removeItem(key: string): void {
    this.#map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.#map.set(key, value);
  }
}

test("agent settings round-trip and are absent until both fields are set", () => {
  const storage = new MapStorage();
  assert.equal(loadAgentSettings(storage), undefined);

  saveAgentSettings(storage, {
    address: "http://127.0.0.1:38217",
    token: "abc123",
    keyId: "org-north-ca",
  });
  assert.deepEqual(loadAgentSettings(storage), {
    address: "http://127.0.0.1:38217",
    token: "abc123",
    keyId: "org-north-ca",
  });
});

test("snapshot verification key round-trips as JWK", () => {
  const storage = new MapStorage();
  assert.equal(loadSnapshotVerifyKey(storage), undefined);

  const jwk: JsonWebKey = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
  saveSnapshotVerifyKey(storage, jwk);
  assert.deepEqual(loadSnapshotVerifyKey(storage), jwk);
});

test("a malformed stored JWK is treated as absent, not thrown", () => {
  const storage = new MapStorage();
  storage.setItem("tessera-issuer-cabinet.snapshot.verify_jwk", "{not json");
  assert.equal(loadSnapshotVerifyKey(storage), undefined);
});

test("explicit locale round-trips and rejects garbage values", () => {
  const storage = new MapStorage();
  assert.equal(loadExplicitLocale(storage), undefined);

  saveExplicitLocale(storage, "ru");
  assert.equal(loadExplicitLocale(storage), "ru");

  storage.setItem("tessera-issuer-cabinet.locale", "fr");
  assert.equal(loadExplicitLocale(storage), undefined);
});
