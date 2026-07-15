// HTTP client for the local `issuer serve` agent (spec `issuer-signing` —
// "Локальный агент issuer serve"; protocol in
// `crates/tessera_issuer/src/serve.rs`). This is the cabinet's only network
// call (spec `issuer-cabinet` — "Никаких внешних обращений"): the CSP in
// `public/index.html` enforces the loopback restriction at the browser
// level, but `assertLoopbackAddress` below re-checks it in this module too
// — an operator-editable address field is one typo away from `connect-src`
// simply blocking a *different* attempt rather than the intended one, and a
// clear rejection here is a better failure mode than "request blocked by
// CSP" with no context about which address was wrong.

import type { AgentAlgorithmTag, AgentInfoResponse, SignatureAlgorithmTag } from "../types.ts";

const SESSION_HEADER = "X-Tessera-Session";

export interface AgentSignResult {
  signatureB64: string;
  algorithm: SignatureAlgorithmTag;
}

export class AgentError extends Error {}

/** Map the agent's wire algorithm vocabulary to the WASM binding's, for `assemble_and_verify`. */
export function agentAlgorithmToWasmTag(agentTag: AgentAlgorithmTag): SignatureAlgorithmTag {
  switch (agentTag) {
    case "ecdsa-with-sha256":
      return "ecdsa-p256";
    case "ecdsa-with-sha384":
      return "ecdsa-p384";
    case "rsa-pkcs1-sha256":
      return "rsa-sha256";
    case "ed25519":
      return "ed25519";
  }
}

/**
 * Whether `address` parses as `http(s)://<loopback-host>[:port]` — exactly
 * `127.0.0.1`, `::1` (bracketed, `[::1]`), or `localhost`, case-insensitive.
 * No path/query/fragment beyond an optional trailing slash, no other host
 * (including other `127.*` addresses, `0.0.0.0`, or a hostname that merely
 * resolves to loopback via DNS — matching `issuer serve`'s own bind to
 * `127.0.0.1` literally, per `crates/tessera_issuer/src/serve.rs`).
 */
export function isLoopbackAgentAddress(address: string): boolean {
  let url: URL;
  try {
    url = new URL(address);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (url.pathname !== "" && url.pathname !== "/") return false;
  if (url.search !== "" || url.hash !== "") return false;
  // The WHATWG URL parser reports an IPv6 host with its brackets intact
  // (`hostname` is `"[::1]"`, not `"::1"`), unlike an IPv4 literal or a name.
  const host = url.hostname.toLowerCase();
  return host === "127.0.0.1" || host === "[::1]" || host === "localhost";
}

/** Throws {@link AgentError} unless `address` is a loopback agent address (see {@link isLoopbackAgentAddress}). */
function assertLoopbackAddress(address: string): void {
  if (!isLoopbackAgentAddress(address)) {
    throw new AgentError(
      `agent address must be http(s)://127.0.0.1, ::1, or localhost — refusing to contact "${address}"`,
    );
  }
}

async function parseJsonOrThrow<T>(response: Response): Promise<T> {
  const text = await response.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new AgentError(`agent returned non-JSON response (status ${response.status})`);
  }
  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as { error: unknown }).error)
        : `agent request failed (status ${response.status})`;
    throw new AgentError(message);
  }
  return body as T;
}

/** `GET /info` — used to confirm the configured agent is reachable and to show its advertised algorithms. */
export async function agentInfo(address: string, token: string): Promise<AgentInfoResponse> {
  assertLoopbackAddress(address);
  let response: Response;
  try {
    response = await fetch(`${address.replace(/\/$/, "")}/info`, {
      method: "GET",
      headers: { [SESSION_HEADER]: token },
    });
  } catch (e) {
    throw new AgentError(`could not reach the agent at ${address}: ${String(e)}`);
  }
  return parseJsonOrThrow<AgentInfoResponse>(response);
}

/** `POST /sign` — send a built TBS to the agent and receive the signature. */
export async function agentSign(
  address: string,
  token: string,
  keyId: string,
  tbsDerB64: string,
): Promise<AgentSignResult> {
  assertLoopbackAddress(address);
  let response: Response;
  try {
    response = await fetch(`${address.replace(/\/$/, "")}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json", [SESSION_HEADER]: token },
      body: JSON.stringify({ key_id: keyId, tbs_der_b64: tbsDerB64 }),
    });
  } catch (e) {
    throw new AgentError(`could not reach the agent at ${address}: ${String(e)}`);
  }
  const parsed = await parseJsonOrThrow<{ signature_b64: string; algorithm: AgentAlgorithmTag }>(
    response,
  );
  return {
    signatureB64: parsed.signature_b64,
    algorithm: agentAlgorithmToWasmTag(parsed.algorithm),
  };
}
