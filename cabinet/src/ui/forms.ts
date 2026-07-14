// The CA, leaf, and CRL issuance forms (spec `issuer-cabinet` — "Предъявлен
// корень парка" / "Предъявлен CA организации"). The CA and leaf forms are
// built from the parent's envelope via `core/envelope.ts`, so a value
// outside the envelope is never offered as an option in the first place;
// `core/envelope.ts`'s `validate*` functions are still run on submit as the
// last client-side gate before the WASM core's own (authoritative) check.

import { maxSelectableLevel, maxSelectableTtl, selectableRoles } from "../core/envelope.ts";
import type { LeafPrefill } from "../core/csrPrefill.ts";
import type { IssuedEntry } from "../core/journalEntries.ts";
import type { Locale } from "../i18n/locale.ts";
import { t } from "../i18n/locale.ts";
import type { CaRequestJson, EnvelopeJson, LeafRequestJson } from "../types.ts";
import { el } from "./dom.ts";
import {
  datetimeLocalToUnix,
  roleCheckboxGroup,
  stringListInput,
  tagListInput,
  unixToDatetimeLocal,
} from "./widgets.ts";

export interface CaFormResult {
  subject: string;
  spkiInput: HTMLInputElement;
  validity: { notBefore?: number; notAfter?: number };
  constraints: EnvelopeJson;
  profileVersion: number;
}

export interface CaFormHandle {
  root: HTMLElement;
  getValue: () => CaFormResult;
}

/** Build the "issue organisation CA" form, scoped to `parent`. */
export function buildCaForm(locale: Locale, parent: EnvelopeJson): CaFormHandle {
  const subjectInput = el("input", { type: "text", placeholder: "CN=Org North CA,O=Org" });
  const spkiInput = el("input", { type: "file" });
  const notBefore = el("input", { type: "datetime-local" });
  const notAfter = el("input", { type: "datetime-local" });
  const profileVersion = el("input", { type: "number", value: "1", min: "1" });

  const roles = roleCheckboxGroup(selectableRoles(parent));
  const maxLevel = el("input", {
    type: "number",
    value: String(maxSelectableLevel(parent)),
    max: String(maxSelectableLevel(parent)),
  });
  const maxTtl = el("input", {
    type: "number",
    value: String(maxSelectableTtl(parent)),
    max: String(maxSelectableTtl(parent)),
  });
  const requireTags = tagListInput(
    t(locale, "field_add"),
    t(locale, "field_remove"),
    parent.require_tags,
  );

  const root = el("div", { class: "form form-ca" }, [
    el("h3", {}, [t(locale, "ca_form_title")]),
    field(t(locale, "field_subject"), subjectInput),
    field(t(locale, "spki_file_label"), spkiInput),
    field(t(locale, "field_not_before"), notBefore),
    field(t(locale, "field_not_after"), notAfter),
    field(t(locale, "field_profile_version"), profileVersion),
    field(t(locale, "ca_field_allow_roles"), roles.root),
    field(t(locale, "ca_field_max_level"), maxLevel),
    field(t(locale, "ca_field_max_ttl"), maxTtl),
    field(t(locale, "ca_field_require_tags"), requireTags.root),
  ]);

  return {
    root,
    getValue: () => ({
      subject: subjectInput.value.trim(),
      spkiInput,
      validity: {
        notBefore: datetimeLocalToUnix(notBefore.value),
        notAfter: datetimeLocalToUnix(notAfter.value),
      },
      constraints: {
        require_tags: requireTags.getValue(),
        allow_roles: roles.getValue(),
        max_level: clampNumber(maxLevel.value, maxSelectableLevel(parent)),
        max_ttl: clampNumber(maxTtl.value, maxSelectableTtl(parent)),
      },
      profileVersion: Number(profileVersion.value) || 1,
    }),
  };
}

export type LeafKeySource = "spki" | "csr";

export interface LeafFormResult {
  subject: string;
  spkiInput: HTMLInputElement;
  validity: { notBefore?: number; notAfter?: number };
  hostBinding: string[];
  userBinding: string[];
  allowedRoles: string[];
  maxIntegrityLevel?: number;
  maxIntegrityCategories?: number;
  profileVersion: number;
}

export interface LeafFormHandle {
  root: HTMLElement;
  keySourceRadios: { spki: HTMLInputElement; csr: HTMLInputElement };
  csrInput: HTMLInputElement;
  spkiSection: HTMLElement;
  subjectInput: HTMLInputElement;
  getValue: () => LeafFormResult;
  /**
   * Apply a CSR-derived prefill (spec `issuer-cabinet` — the prefilled
   * fields must be "явно помечено как «запрошено в CSR» и редактируемо").
   * Sets the given fields' values and shows a "requested in CSR" marker next
   * to each one that was actually applied; roles/integrity the CSR asked for
   * but the envelope excludes are surfaced via `rejected`, not silently
   * dropped.
   */
  applyCsrPrefill: (prefill: LeafPrefill) => void;
}

/** Build the "issue shift leaf" form, scoped to `parent`. */
export function buildLeafForm(locale: Locale, parent: EnvelopeJson): LeafFormHandle {
  const spkiRadio = el("input", { type: "radio", name: "leaf-key-source", value: "spki", checked: "checked" });
  const csrRadio = el("input", { type: "radio", name: "leaf-key-source", value: "csr" });
  const keySourceRow = el("div", { class: "key-source-picker" }, [
    el("label", {}, [spkiRadio, t(locale, "key_source_spki")]),
    el("label", {}, [csrRadio, t(locale, "key_source_csr")]),
  ]);

  const subjectInput = el("input", { type: "text", placeholder: "CN=ivanov,O=Org" });
  const spkiInput = el("input", { type: "file" });
  const spkiSection = el("div", { class: "leaf-spki-section" }, [
    field(t(locale, "field_subject"), subjectInput),
    field(t(locale, "spki_file_label"), spkiInput),
  ]);

  const csrInput = el("input", { type: "file" });
  const csrSection = el("div", { class: "leaf-csr-section hidden" }, [
    field(t(locale, "csr_file_label"), csrInput),
  ]);

  spkiRadio.addEventListener("change", () => {
    spkiSection.classList.remove("hidden");
    csrSection.classList.add("hidden");
  });
  csrRadio.addEventListener("change", () => {
    spkiSection.classList.add("hidden");
    csrSection.classList.remove("hidden");
  });

  const notBefore = el("input", { type: "datetime-local" });
  const notAfter = el("input", { type: "datetime-local" });
  const hostBinding = stringListInput(t(locale, "field_add"), t(locale, "field_remove"));
  const userBinding = stringListInput(t(locale, "field_add"), t(locale, "field_remove"));
  const roles = roleCheckboxGroup(selectableRoles(parent));
  const maxLevel = el("input", {
    type: "number",
    max: String(maxSelectableLevel(parent)),
  });
  const maxCategories = el("input", { type: "text", placeholder: "0x1" });
  const profileVersion = el("input", { type: "number", value: "1", min: "1" });

  // Markers shown next to a field once a value was actually applied from a
  // CSR's requested extensions; toggled by `applyCsrPrefill` below.
  const hostMarker = prefillMarker(locale);
  const userMarker = prefillMarker(locale);
  const rolesMarker = prefillMarker(locale);
  const integrityMarker = prefillMarker(locale);
  const profileMarker = prefillMarker(locale);
  const rejectedNote = el("p", { class: "hint csr-rejected-note hidden" });

  const root = el("div", { class: "form form-leaf" }, [
    el("h3", {}, [t(locale, "leaf_form_title")]),
    field(t(locale, "key_source_label"), keySourceRow),
    spkiSection,
    csrSection,
    field(t(locale, "field_not_before"), notBefore),
    field(t(locale, "field_not_after"), notAfter),
    fieldWithMarker(t(locale, "field_host_binding"), hostBinding.root, hostMarker),
    fieldWithMarker(t(locale, "field_user_binding"), userBinding.root, userMarker),
    fieldWithMarker(t(locale, "field_allowed_roles"), roles.root, rolesMarker),
    fieldWithMarker(t(locale, "field_max_integrity_level"), maxLevel, integrityMarker),
    field(t(locale, "field_max_integrity_categories"), maxCategories),
    fieldWithMarker(t(locale, "field_profile_version"), profileVersion, profileMarker),
    rejectedNote,
  ]);

  function applyCsrPrefill(prefill: LeafPrefill): void {
    if (prefill.hostBinding) {
      hostBinding.setValue(prefill.hostBinding);
      hostMarker.classList.remove("hidden");
    }
    if (prefill.userBinding) {
      userBinding.setValue(prefill.userBinding);
      userMarker.classList.remove("hidden");
    }
    if (prefill.allowedRoles) {
      roles.setValue(prefill.allowedRoles);
      rolesMarker.classList.remove("hidden");
    }
    if (prefill.maxIntegrityLevel !== undefined) {
      maxLevel.value = String(prefill.maxIntegrityLevel);
      maxCategories.value =
        prefill.maxIntegrityCategories !== undefined
          ? `0x${prefill.maxIntegrityCategories.toString(16)}`
          : maxCategories.value;
      integrityMarker.classList.remove("hidden");
    }
    if (prefill.profileVersion !== undefined) {
      profileVersion.value = String(prefill.profileVersion);
      profileMarker.classList.remove("hidden");
    }

    const rejections: string[] = [];
    if (prefill.rejectedRoles.length > 0) {
      rejections.push(`${t(locale, "csr_rejected_roles")}: ${prefill.rejectedRoles.join(", ")}`);
    }
    if (prefill.rejectedIntegrityLevel !== undefined) {
      rejections.push(`${t(locale, "csr_rejected_integrity")}: ${prefill.rejectedIntegrityLevel}`);
    }
    if (rejections.length > 0) {
      rejectedNote.textContent = rejections.join("; ");
      rejectedNote.classList.remove("hidden");
    } else {
      rejectedNote.classList.add("hidden");
    }
  }

  return {
    root,
    keySourceRadios: { spki: spkiRadio, csr: csrRadio },
    csrInput,
    spkiSection,
    subjectInput,
    getValue: () => ({
      subject: subjectInput.value.trim(),
      spkiInput,
      validity: {
        notBefore: datetimeLocalToUnix(notBefore.value),
        notAfter: datetimeLocalToUnix(notAfter.value),
      },
      hostBinding: hostBinding.getValue(),
      userBinding: userBinding.getValue(),
      allowedRoles: roles.getValue(),
      maxIntegrityLevel: maxLevel.value ? Number(maxLevel.value) : undefined,
      maxIntegrityCategories: maxCategories.value ? parseHexOrDecimal(maxCategories.value) : undefined,
      profileVersion: Number(profileVersion.value) || 1,
    }),
    applyCsrPrefill,
  };
}

export interface CrlFormResult {
  thisUpdate?: number;
  nextUpdate?: number;
  crlNumber: number;
  revoked: { serialHex: string; revocationDate: number }[];
}

export interface CrlFormHandle {
  root: HTMLElement;
  getValue: () => CrlFormResult;
}

/**
 * Build the "issue CRL" form for the CA fingerprinted by the loaded parent
 * certificate. `lastNumber` and `candidates` come from parsing the
 * in-memory journal (`core/journalEntries.ts`) — both are conveniences the
 * operator can override or extend, not requirements (the journal is
 * secondary evidence, per `issuance-journal`).
 */
export function buildCrlForm(
  locale: Locale,
  lastNumber: number,
  candidates: IssuedEntry[],
): CrlFormHandle {
  const thisUpdate = el("input", { type: "datetime-local" });
  const nextUpdate = el("input", { type: "datetime-local" });
  const crlNumber = el("input", { type: "number", value: String(lastNumber + 1), min: String(lastNumber + 1) });
  const lastNumberDisplay = el("p", { class: "hint" }, [
    `${t(locale, "crl_last_number_label")}: ${lastNumber}`,
  ]);

  const candidateBoxes: { input: HTMLInputElement; serialHex: string }[] = [];
  const candidatesList =
    candidates.length > 0
      ? el(
          "div",
          { class: "crl-candidates" },
          candidates.map((c) => {
            const input = el("input", { type: "checkbox", value: c.serialHex });
            candidateBoxes.push({ input, serialHex: c.serialHex });
            return el("label", { class: "crl-candidate-row" }, [
              input,
              ` ${c.serialHex} — ${c.subject}`,
            ]);
          }),
        )
      : el("p", { class: "hint" }, [t(locale, "crl_candidates_none")]);

  const extraRevoked = stringListInput(t(locale, "field_add"), t(locale, "field_remove"));

  const root = el("div", { class: "form form-crl" }, [
    el("h3", {}, [t(locale, "crl_form_title")]),
    lastNumberDisplay,
    field(t(locale, "crl_field_crl_number"), crlNumber),
    field(t(locale, "crl_field_this_update"), thisUpdate),
    field(t(locale, "crl_field_next_update"), nextUpdate),
    field(t(locale, "crl_candidates_label"), candidatesList),
    field(`${t(locale, "crl_field_serial")} (${t(locale, "field_add")})`, extraRevoked.root),
  ]);

  return {
    root,
    getValue: () => {
      const now = Math.floor(Date.now() / 1000);
      const revoked: { serialHex: string; revocationDate: number }[] = [];
      for (const box of candidateBoxes) {
        if (box.input.checked) revoked.push({ serialHex: box.serialHex, revocationDate: now });
      }
      for (const serialHex of extraRevoked.getValue()) {
        revoked.push({ serialHex, revocationDate: now });
      }
      return {
        thisUpdate: datetimeLocalToUnix(thisUpdate.value),
        nextUpdate: datetimeLocalToUnix(nextUpdate.value),
        crlNumber: Number(crlNumber.value) || lastNumber + 1,
        revoked,
      };
    },
  };
}

function clampNumber(raw: string, ceiling: number): number {
  const value = Number(raw);
  if (Number.isNaN(value)) return 0;
  return Math.min(value, ceiling);
}

function parseHexOrDecimal(raw: string): number | undefined {
  const trimmed = raw.trim();
  const value = trimmed.startsWith("0x") ? parseInt(trimmed, 16) : Number(trimmed);
  return Number.isNaN(value) ? undefined : value;
}

function field(label: string, input: HTMLElement): HTMLElement {
  return el("div", { class: "field" }, [el("label", {}, [label]), input]);
}

function fieldWithMarker(label: string, input: HTMLElement, marker: HTMLElement): HTMLElement {
  return el("div", { class: "field" }, [
    el("label", {}, [label, marker]),
    input,
  ]);
}

function prefillMarker(locale: Locale): HTMLElement {
  return el("span", { class: "csr-prefill-marker hidden" }, [` (${t(locale, "csr_prefill_marker")})`]);
}

/** Round-trip a Unix timestamp through the `datetime-local` widget format, for prefill. */
export function prefillDatetime(seconds: number): string {
  return unixToDatetimeLocal(seconds);
}

export type { CaRequestJson, LeafRequestJson };
