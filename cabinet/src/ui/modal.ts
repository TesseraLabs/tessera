// Reusable help modal (spec design §3 "Справки"): local DOM only, no
// external resources — the cabinet's CSP is `default-src 'self'` and modals
// must not need an exception to it. One modal open at a time; opening a new
// one closes whatever was open first.

import { el } from "./dom.ts";

interface OpenModalState {
  overlay: HTMLElement;
  previousFocus: HTMLElement | null;
  onKeydown: (e: KeyboardEvent) => void;
}

let current: OpenModalState | undefined;
let modalInstanceCounter = 0;

/** Every element inside `panel` that can currently take keyboard focus, in DOM/tab order. */
function focusableElements(panel: HTMLElement): HTMLElement[] {
  const selector =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(panel.querySelectorAll<HTMLElement>(selector));
}

/**
 * Open a modal titled `title` with `bodyNodes` as its content, and an
 * `closeLabel`-labelled close button. Closes on Esc, on a click on the
 * overlay backdrop (not the panel itself), or via the close button; in every
 * case focus returns to whatever element had it before the modal opened
 * (typically the "?" button that triggered it). While open, Tab/Shift+Tab
 * cycle only through the panel's own focusable elements (a minimal focus
 * trap) — focus never silently lands on something behind the overlay.
 */
export function openModal(title: string, bodyNodes: (Node | string)[], closeLabel: string): void {
  closeModal();
  const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  modalInstanceCounter += 1;
  const titleId = `modal-title-${modalInstanceCounter}`;

  const closeBtn = el("button", { type: "button", class: "modal-close" }, [closeLabel]);
  const panel = el(
    "div",
    { class: "modal-panel", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
    [
      el("div", { class: "modal-header" }, [el("h2", { id: titleId }, [title]), closeBtn]),
      el("div", { class: "modal-body" }, bodyNodes),
    ],
  );
  const overlay = el("div", { class: "modal-overlay" }, [panel]);

  closeBtn.addEventListener("click", () => closeModal());
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeModal();
  });
  const onKeydown = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      closeModal();
      return;
    }
    if (e.key !== "Tab") return;
    const focusable = focusableElements(panel);
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !panel.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !panel.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    }
  };
  document.addEventListener("keydown", onKeydown);

  document.body.append(overlay);
  closeBtn.focus();

  current = { overlay, previousFocus, onKeydown };
}

/** Close the currently open modal, if any, and restore focus. Safe to call when nothing is open. */
export function closeModal(): void {
  if (!current) return;
  document.removeEventListener("keydown", current.onKeydown);
  current.overlay.remove();
  current.previousFocus?.focus();
  current = undefined;
}
