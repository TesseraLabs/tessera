import { App } from "./ui/app.ts";

const root = document.getElementById("app");
if (!root) {
  throw new Error("missing #app mount point");
}

// `App.start()` itself never rejects — it renders a fail-closed error
// screen for any WASM-init failure (`core/startupError.ts`). This catch is
// defense in depth for a failure `start()` can't localize into that screen:
// the `App` constructor throwing before `this.#locale` exists (a corrupt
// `sessionStorage` value, for instance), or a bug that lets a rejection
// through unnoticed. It cannot assume a locale, so the message is bilingual
// plain text rather than going through the RU/EN dictionary.
try {
  const app = new App(root, window.sessionStorage, window.location.hostname, navigator.language);
  app.start().catch((e: unknown) => {
    renderFatalError(root, e);
  });
} catch (e) {
  renderFatalError(root, e);
}

function renderFatalError(mount: HTMLElement, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  mount.textContent =
    `Tessera Issuer Cabinet failed to start / Кабинет Tessera не смог запуститься: ${message}`;
}
