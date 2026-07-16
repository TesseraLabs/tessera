// When the cabinet is served by the local signing agent itself
// (`issuer serve --serve-cabinet`/`--cabinet-dir`, design `issuer-local-cabinet`
// §2), the agent injects a paired session token into the returned
// `index.html`'s `<head>` as two `<meta>` tags:
//
//   <meta name="tessera-agent-token" content="<paired session token>">
//   <meta name="tessera-agent-key" content="<CA key label, from --key>">
//
// The agent's address is never injected: the cabinet was served by the agent
// itself, so it is same-origin with `/sign` — the caller passes
// `window.location.origin` as `origin`. `metaLookup` is injected rather than
// reading `document` directly so this stays testable without a DOM.

import type { AgentSettings } from "../state/sessionConfig.ts";

const META_TOKEN = "tessera-agent-token";
const META_KEY = "tessera-agent-key";

/**
 * Reads the agent's same-origin session injection, if present. Returns
 * `undefined` when there is no (or an empty) token meta tag — i.e. the
 * cabinet was not served by the agent (external hosting/dev), and the
 * operator falls back to manual entry.
 */
export function readAgentInjection(
  metaLookup: (name: string) => string | null,
  origin: string,
): AgentSettings | undefined {
  const token = metaLookup(META_TOKEN);
  if (!token) return undefined;
  const keyId = metaLookup(META_KEY) ?? "";
  return { address: origin, token, keyId };
}
