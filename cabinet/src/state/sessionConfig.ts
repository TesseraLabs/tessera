// Session-scoped operator config: the agent address/token (spec
// `issuer-cabinet` — the split-signing flow) and the snapshot verification
// key (spec — "Инвентарь для форм"). All of this is entered by the operator
// and never written to disk: `sessionStorage` clears it when the tab closes,
// matching the "stateless statics, state lives in files" serverless
// invariant — this is session UI convenience, not persisted cabinet state.
//
// `Storage` (the `sessionStorage`/`localStorage` interface) is accepted as a
// parameter rather than imported globally, so this module is testable
// without a DOM.

export interface AgentSettings {
  address: string;
  token: string;
  /**
   * The CA key label the agent was started with (`issuer serve --key`,
   * `crates/tessera_issuer/src/pkcs11.rs`): the backend rejects a `/sign`
   * request whose `key_id` does not match it exactly, so the operator must
   * enter the same value here.
   */
  keyId: string;
}

const KEY_AGENT_ADDRESS = "tessera-issuer-cabinet.agent.address";
const KEY_AGENT_TOKEN = "tessera-issuer-cabinet.agent.token";
const KEY_AGENT_KEY_ID = "tessera-issuer-cabinet.agent.key_id";
const KEY_SNAPSHOT_VERIFY_JWK = "tessera-issuer-cabinet.snapshot.verify_jwk";
const KEY_LOCALE = "tessera-issuer-cabinet.locale";

export function loadAgentSettings(storage: Storage): AgentSettings | undefined {
  const address = storage.getItem(KEY_AGENT_ADDRESS);
  const token = storage.getItem(KEY_AGENT_TOKEN);
  const keyId = storage.getItem(KEY_AGENT_KEY_ID);
  if (!address || !token || !keyId) return undefined;
  return { address, token, keyId };
}

export function saveAgentSettings(storage: Storage, settings: AgentSettings): void {
  storage.setItem(KEY_AGENT_ADDRESS, settings.address);
  storage.setItem(KEY_AGENT_TOKEN, settings.token);
  storage.setItem(KEY_AGENT_KEY_ID, settings.keyId);
}

export function loadSnapshotVerifyKey(storage: Storage): JsonWebKey | undefined {
  const raw = storage.getItem(KEY_SNAPSHOT_VERIFY_JWK);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as JsonWebKey;
  } catch {
    return undefined;
  }
}

export function saveSnapshotVerifyKey(storage: Storage, jwk: JsonWebKey): void {
  storage.setItem(KEY_SNAPSHOT_VERIFY_JWK, JSON.stringify(jwk));
}

export function loadExplicitLocale(storage: Storage): "ru" | "en" | undefined {
  const raw = storage.getItem(KEY_LOCALE);
  return raw === "ru" || raw === "en" ? raw : undefined;
}

export function saveExplicitLocale(storage: Storage, locale: "ru" | "en"): void {
  storage.setItem(KEY_LOCALE, locale);
}
