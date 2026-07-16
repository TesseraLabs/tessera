// The cabinet's top-level controller: owns session state, renders every
// section, and wires the split-signing flow end to end (spec
// `issuer-cabinet` + `issuer-signing`). Deliberately one file: the state
// machine is small (parent → operation form(s) → summary → sign → journal)
// and splitting it across files would scatter the flow the spec describes
// as a single linear scenario, without a real reuse benefit — the reusable
// parts already live in `core/*` and `ui/forms.ts`/`ui/widgets.ts`.

import { agentInfo, agentSign, AgentError } from "../core/agentClient.ts";
import { readAgentInjection } from "../core/agentInjection.ts";
import { computeLeafPrefill } from "../core/csrPrefill.ts";
import { parseApiError, renderApiError } from "../core/errorLabels.ts";
import { validateChildEnvelope, validateLeafSelection } from "../core/envelope.ts";
import { sha256HexOfDer } from "../core/fingerprint.ts";
import { parseJournalFile, renderJournalFile, renderJournalStatus } from "../core/journal.ts";
import { lastCrlNumber, revocationCandidates } from "../core/journalEntries.ts";
import { pemOrDer } from "../core/pem.ts";
import {
  acceptSnapshot,
  buildManualSnapshot,
  type AcceptedSnapshot,
  type SnapshotPayload,
} from "../core/snapshot.ts";
import { startupErrorText } from "../core/startupError.ts";
import {
  assembleAndVerify,
  buildCaTbs,
  buildCrlTbs,
  buildLeafTbs,
  ensureWasmReady,
  inspectCsr,
  inspectParent,
  journalAppend,
  journalVerify,
  randomSerialEntropyB64,
} from "../core/wasmBridge.ts";
import { t, type Locale, resolveLocale } from "../i18n/locale.ts";
import {
  loadAgentSettings,
  loadExplicitLocale,
  loadSnapshotVerifyKey,
  saveAgentSettings,
  saveExplicitLocale,
  saveSnapshotVerifyKey,
  type AgentSettings,
} from "../state/sessionConfig.ts";
import type {
  EnvelopeJson,
  InspectParentResponse,
  JournalEntryJson,
  SignatureAlgorithmTag,
} from "../types.ts";
import { downloadText, el, readFileAsBase64, readFileAsText } from "./dom.ts";
import {
  buildCaForm,
  buildCrlForm,
  buildLeafForm,
  type CaFormHandle,
  type CrlFormHandle,
  type LeafFormHandle,
} from "./forms.ts";
import { openModal } from "./modal.ts";
import { hostListInput, stringListInput, tagListInput } from "./widgets.ts";

const ALGORITHMS: SignatureAlgorithmTag[] = ["ecdsa-p256", "ecdsa-p384", "rsa-sha256", "ed25519"];

/** Literal CLI example for the agent help modal (design §3) — technical, not localized, mirrors `docs/{ru,en}/issuer.md` §"Агент issuer serve". */
const AGENT_SERVE_EXAMPLE = `issuer serve \\
    --allow-origin https://cabinet.example \\
    --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \\
    --key tessera-ca --algorithm ecdsa-p256 \\
    --port 0`;

type Tab = "issue" | "journal";
type SnapshotMode = "manual" | "file";
/**
 * The signing agent's reachability, tracked separately from a per-check
 * result so the indicator survives a re-render/tab switch (design §4):
 * `"unknown"` — never checked (or the settings changed since); `"connecting"`
 * — a check is in flight; `"connected"`/`"error"` — the last check's outcome.
 */
type AgentStatus = "unknown" | "connecting" | "connected" | "error";

interface PendingOperation {
  kind: "org_ca" | "shift_leaf" | "crl";
  tbsB64: string;
  parentB64: string;
  algorithm: SignatureAlgorithmTag;
  renderedSummary: string;
  journalEntry: (serialB64: string) => JournalEntryJson;
}

export class App {
  #root: HTMLElement;
  #storage: Storage;
  #locale: Locale;

  /** Base64 **DER** of the loaded parent/issuer certificate (PEM depemmed client-side — see `core/pem.ts`). */
  #parentDerB64?: string;
  /** Lowercase-hex SHA-256 of the parent DER — matches the journal's own "parent" fingerprint field. */
  #parentFingerprintHex?: string;
  #parentInfo?: InspectParentResponse;
  #snapshot?: AcceptedSnapshot;
  #snapshotMode: SnapshotMode = "manual";
  #agentSettings?: AgentSettings;
  /**
   * Set once, in the constructor, from whether {@link readAgentInjection}
   * returned a settled value — i.e. this page was served by the local agent
   * itself (design `issuer-local-cabinet` §2), not hosted externally. Drives
   * the compact agent section (status only, no editable fields) and the
   * automatic connectivity check on startup.
   */
  #agentInjected: boolean;
  #agentStatus: AgentStatus = "unknown";
  #journalLines: string[] = [];
  #pending?: PendingOperation;
  #error?: string;
  #activeTab: Tab = "issue";

  constructor(
    root: HTMLElement,
    storage: Storage,
    hostname: string,
    browserLanguage: string | undefined,
    agentMetaLookup: (name: string) => string | null,
    origin: string,
  ) {
    this.#root = root;
    this.#storage = storage;
    this.#locale = resolveLocale({
      explicit: loadExplicitLocale(storage),
      hostname,
      browserLanguage,
    });
    // The agent-served injection (design `issuer-local-cabinet` §2) is the
    // source of truth for *this* run when present — it means the page was
    // just served by the agent itself — and overrides whatever was saved
    // from a previous session. When there is no injection (external
    // hosting/dev), previously saved settings are left untouched.
    const injected = readAgentInjection(agentMetaLookup, origin);
    this.#agentInjected = injected !== undefined;
    this.#agentSettings = injected ?? loadAgentSettings(storage);
  }

  /**
   * Never rejects: a failure to initialise the WASM core (CSP blocking
   * `WebAssembly.instantiate`, a missing/corrupt `.wasm` artifact, an
   * unsupported browser) renders a fail-closed error screen instead of
   * leaving `#app` empty. `main.ts` still wraps the call for defense in
   * depth against a failure this method itself can't catch (e.g. the
   * constructor throwing before `this.#locale` exists).
   */
  async start(): Promise<void> {
    try {
      await ensureWasmReady();
    } catch (e) {
      this.renderStartupError(e);
      return;
    }
    this.render();
    // Injected settings are known-good by construction (the agent just
    // served this page with them) — the compact agent section has no
    // "Подключить" button to trigger a check, so it happens once here
    // instead. The compact view has no editable fields to lose, so a full
    // re-render on completion is safe (unlike the manual-entry flow's
    // in-place indicator update, which guards against clobbering unsaved
    // input elsewhere in that section).
    if (this.#agentInjected && this.#agentSettings) {
      void this.autoCheckAgentConnection(this.#agentSettings);
    }
  }

  private async autoCheckAgentConnection(settings: AgentSettings): Promise<void> {
    this.#agentStatus = "connecting";
    this.render();
    try {
      await agentInfo(settings.address, settings.token);
      this.#agentStatus = "connected";
    } catch {
      this.#agentStatus = "error";
    }
    this.render();
  }

  private renderStartupError(error: unknown): void {
    const text = startupErrorText(this.#locale, error);
    this.#root.replaceChildren(
      el("div", { class: "startup-error" }, [
        el("h1", {}, [text.title]),
        el("p", {}, [text.detail]),
      ]),
    );
  }

  private setLocale(locale: Locale): void {
    this.#locale = locale;
    saveExplicitLocale(this.#storage, locale);
    this.render();
  }

  private setError(message: string | undefined): void {
    this.#error = message;
    this.render();
  }

  // --- render -----------------------------------------------------------

  render(): void {
    const issueTabNodes = [
      this.renderParentSection(),
      this.#parentInfo ? this.renderOperationSection() : "",
      this.renderSnapshotSection(),
      this.renderAgentSection(),
      this.#pending ? this.renderSummarySection() : "",
    ];
    this.#root.replaceChildren(
      this.renderHeader(),
      this.renderTabBar(),
      this.#error ? el("div", { class: "banner banner-error" }, [this.#error]) : "",
      ...(this.#activeTab === "issue" ? issueTabNodes : [this.renderJournalSection()]),
    );
  }

  private setActiveTab(tab: Tab): void {
    this.#activeTab = tab;
    this.render();
  }

  private renderTabBar(): HTMLElement {
    const issueBtn = el(
      "button",
      { type: "button", class: this.#activeTab === "issue" ? "active" : "" },
      [this.t("tab_issue")],
    );
    const journalBtn = el(
      "button",
      { type: "button", class: this.#activeTab === "journal" ? "active" : "" },
      [this.t("tab_journal")],
    );
    issueBtn.addEventListener("click", () => this.setActiveTab("issue"));
    journalBtn.addEventListener("click", () => this.setActiveTab("journal"));
    return el("nav", { class: "tab-bar" }, [issueBtn, journalBtn]);
  }

  private helpButton(titleKey: "help_parent_title" | "help_agent_title", body: (Node | string)[]): HTMLElement {
    const btn = el("button", { type: "button", class: "btn-help", "aria-label": this.t("help_button_label") }, [
      "?",
    ]);
    btn.addEventListener("click", () => {
      openModal(this.t(titleKey), body, this.t("action_close"));
    });
    return btn;
  }

  private t(key: Parameters<typeof t>[1]): string {
    return t(this.#locale, key);
  }

  private renderHeader(): HTMLElement {
    const ruBtn = el("button", { type: "button", class: this.#locale === "ru" ? "active" : "" }, [
      this.t("lang_switch_ru"),
    ]);
    const enBtn = el("button", { type: "button", class: this.#locale === "en" ? "active" : "" }, [
      this.t("lang_switch_en"),
    ]);
    ruBtn.addEventListener("click", () => this.setLocale("ru"));
    enBtn.addEventListener("click", () => this.setLocale("en"));
    return el("header", { class: "app-header" }, [
      el("h1", {}, [this.t("app_title")]),
      el("div", { class: "lang-switch" }, [ruBtn, enBtn]),
    ]);
  }

  // --- parent -------------------------------------------------------------

  private renderParentSection(): HTMLElement {
    const fileInput = el("input", { type: "file", accept: ".pem,.der,.crt,.cer" });
    fileInput.addEventListener("change", () => {
      void this.onParentFileChosen(fileInput);
    });

    const status = this.#parentInfo
      ? this.renderParentStatus(this.#parentInfo)
      : el("p", { class: "hint" }, [this.t("parent_no_parent")]);

    const helpBtn = this.helpButton("help_parent_title", [
      el("p", {}, [this.t("help_parent_p1")]),
      el("p", {}, [this.t("help_parent_p2")]),
      el("p", {}, [this.t("help_parent_p3")]),
      el("p", { class: "hint" }, [`${this.t("help_docs_more")}: docs/issuer.md`]),
    ]);

    return el("section", { class: "section section-parent" }, [
      el("h2", { class: "section-heading" }, [this.t("parent_file_label"), helpBtn]),
      el("p", { class: "hint" }, [this.t("parent_file_hint")]),
      fileInput,
      status,
    ]);
  }

  private renderParentStatus(info: InspectParentResponse): HTMLElement {
    const kindLabel =
      info.kind === "root"
        ? this.t("parent_kind_root")
        : info.kind === "org_ca"
          ? this.t("parent_kind_org_ca")
          : info.kind === "leaf"
            ? this.t("parent_kind_leaf")
            : this.t("parent_kind_unusable");
    const desc =
      info.kind === "root"
        ? this.t("parent_kind_root_desc")
        : info.kind === "org_ca"
          ? this.t("parent_kind_org_ca_desc")
          : info.kind === "leaf"
            ? this.t("parent_kind_leaf_desc")
            : (info.reason ?? "");

    const envelopeBlock = info.envelope
      ? el("div", { class: "envelope-summary" }, [
          el("h3", {}, [this.t("parent_envelope_title")]),
          el("dl", {}, [
            el("dt", {}, [this.t("envelope_allow_roles")]),
            el("dd", {}, [info.envelope.allow_roles.join(", ") || "—"]),
            el("dt", {}, [this.t("envelope_max_level")]),
            el("dd", {}, [String(info.envelope.max_level)]),
            el("dt", {}, [this.t("envelope_max_ttl")]),
            el("dd", {}, [String(info.envelope.max_ttl)]),
            el("dt", {}, [this.t("envelope_require_tags")]),
            el("dd", {}, [
              info.envelope.require_tags.map(([k, v]) => `${k}=${v}`).join(", ") || "—",
            ]),
          ]),
        ])
      : "";

    return el("div", { class: `parent-status parent-kind-${info.kind}` }, [
      el("p", {}, [el("strong", {}, [kindLabel])]),
      el("p", {}, [`${this.t("parent_subject")}: ${info.subject || "—"}`]),
      el("p", { class: "hint" }, [desc]),
      envelopeBlock,
    ]);
  }

  private async onParentFileChosen(input: HTMLInputElement): Promise<void> {
    try {
      const rawB64 = await readFileAsBase64(input);
      const derBytes = pemOrDer(base64ToBytes(rawB64));
      const derB64 = bytesToBase64(derBytes);
      const info = await inspectParent(derB64);
      this.#parentDerB64 = derB64;
      this.#parentFingerprintHex = await sha256HexOfDer(derBytes);
      this.#parentInfo = info;
      this.#error = undefined;
    } catch (e) {
      this.#error = renderApiError(this.#locale, parseApiError(e));
    }
    this.render();
  }

  // --- operation ------------------------------------------------------

  private renderOperationSection(): HTMLElement {
    const info = this.#parentInfo;
    if (!info) return el("section", {});
    if (info.kind === "root" && info.envelope) {
      return el("div", { class: "operation-group" }, [
        this.renderCaOperation(info.envelope),
        this.renderCrlOperation(),
      ]);
    }
    if (info.kind === "org_ca" && info.envelope) {
      return el("div", { class: "operation-group" }, [
        this.renderLeafOperation(info.envelope),
        this.renderCrlOperation(),
      ]);
    }
    return el("section", { class: "section section-operation" }, [
      el("h2", {}, [this.t("section_operation")]),
      el("p", { class: "hint" }, [info.reason ?? this.t("parent_kind_unusable")]),
    ]);
  }

  private renderCaOperation(envelope: EnvelopeJson): HTMLElement {
    const form: CaFormHandle = buildCaForm(this.#locale, envelope, this.#snapshot?.payload);
    const algorithmSelect = algorithmSelectWidget();
    const buildBtn = el("button", { type: "button", class: "btn-primary" }, [
      this.t("action_build_summary"),
    ]);
    buildBtn.addEventListener("click", () => {
      void this.onBuildCa(form, envelope, algorithmSelect.value as SignatureAlgorithmTag);
    });
    return el("section", { class: "section section-operation" }, [
      form.root,
      field(this.t("field_algorithm"), algorithmSelect),
      buildBtn,
    ]);
  }

  private async onBuildCa(
    form: CaFormHandle,
    parentEnvelope: EnvelopeJson,
    algorithm: SignatureAlgorithmTag,
  ): Promise<void> {
    if (!this.#parentDerB64) return;
    const parentDerB64 = this.#parentDerB64;
    const value = form.getValue();
    const violations = validateChildEnvelope(parentEnvelope, value.constraints);
    if (violations.length > 0) {
      this.setError(violations.map((v) => v.message).join("; "));
      return;
    }
    if (!value.subject || value.validity.notBefore === undefined || value.validity.notAfter === undefined) {
      this.setError("subject and validity are required");
      return;
    }
    try {
      const spkiB64 = await readFileAsBase64(value.spkiInput);
      const result = await buildCaTbs({
        parent_b64: parentDerB64,
        algorithm,
        serial_entropy_b64: randomSerialEntropyB64(),
        locale: this.#locale,
        request: {
          subject: value.subject,
          spki_b64: spkiB64,
          validity: { not_before: value.validity.notBefore, not_after: value.validity.notAfter },
          constraints: value.constraints,
          profile_version: value.profileVersion,
        },
      });
      this.#pending = {
        kind: "org_ca",
        tbsB64: result.tbs_b64,
        parentB64: parentDerB64,
        algorithm,
        renderedSummary: result.summary.rendered,
        journalEntry: (serialB64) => ({
          op: "issue_ca",
          serial_b64: serialB64,
          parent_b64: parentDerB64,
          subject: value.subject,
        }),
      };
      this.#error = undefined;
    } catch (e) {
      this.setError(renderApiError(this.#locale, parseApiError(e)));
      return;
    }
    this.render();
  }

  private renderLeafOperation(envelope: EnvelopeJson): HTMLElement {
    const form: LeafFormHandle = buildLeafForm(this.#locale, envelope, this.#snapshot?.payload);
    const algorithmSelect = algorithmSelectWidget();
    const csrStatus = el("div", { class: "csr-status" });

    let csrB64: string | undefined;
    form.csrInput.addEventListener("change", () => {
      void (async () => {
        try {
          csrB64 = await readFileAsBase64(form.csrInput);
          const inspected = await inspectCsr(csrB64);
          csrStatus.replaceChildren(
            el("p", {}, [`${this.t("csr_subject")}: ${inspected.subject}`]),
            el("p", {}, [
              `${this.t("csr_signature_valid")}: `,
              inspected.signature_valid
                ? this.t("csr_signature_ok")
                : this.t("csr_signature_bad"),
            ]),
          );
          if (inspected.signature_valid) {
            const prefill = computeLeafPrefill(envelope, inspected.requested_parsed);
            form.applyCsrPrefill(prefill);
          }
        } catch (e) {
          csrB64 = undefined;
          csrStatus.replaceChildren(
            el("p", { class: "error" }, [renderApiError(this.#locale, parseApiError(e))]),
          );
        }
      })();
    });

    const buildBtn = el("button", { type: "button", class: "btn-primary" }, [
      this.t("action_build_summary"),
    ]);
    buildBtn.addEventListener("click", () => {
      void this.onBuildLeaf(form, envelope, algorithmSelect.value as SignatureAlgorithmTag, () => csrB64);
    });

    return el("section", { class: "section section-operation" }, [
      form.root,
      csrStatus,
      field(this.t("field_algorithm"), algorithmSelect),
      buildBtn,
    ]);
  }

  private async onBuildLeaf(
    form: LeafFormHandle,
    parentEnvelope: EnvelopeJson,
    algorithm: SignatureAlgorithmTag,
    getCsrB64: () => string | undefined,
  ): Promise<void> {
    if (!this.#parentDerB64) return;
    const parentDerB64 = this.#parentDerB64;
    const value = form.getValue();
    const usingCsr = form.keySourceRadios.csr.checked;

    const violations = validateLeafSelection(parentEnvelope, {
      allowedRoles: value.allowedRoles,
      maxIntegrityLevel: value.maxIntegrityLevel,
    });
    if (violations.length > 0) {
      this.setError(violations.map((v) => v.message).join("; "));
      return;
    }
    if (value.validity.notBefore === undefined || value.validity.notAfter === undefined) {
      this.setError("validity is required");
      return;
    }
    if (value.hostBinding.length === 0 || value.userBinding.length === 0) {
      this.setError("host_binding and user_binding must not be empty");
      return;
    }

    try {
      const maxIntegrity =
        value.maxIntegrityLevel !== undefined
          ? { level: value.maxIntegrityLevel, categories: value.maxIntegrityCategories ?? 0 }
          : undefined;
      const request = usingCsr
        ? {
            csr_b64: getCsrB64(),
            validity: { not_before: value.validity.notBefore, not_after: value.validity.notAfter },
            host_binding: value.hostBinding,
            user_binding: value.userBinding,
            allowed_roles: value.allowedRoles,
            max_integrity: maxIntegrity,
            profile_version: value.profileVersion,
          }
        : {
            subject: value.subject,
            spki_b64: await readFileAsBase64(value.spkiInput),
            validity: { not_before: value.validity.notBefore, not_after: value.validity.notAfter },
            host_binding: value.hostBinding,
            user_binding: value.userBinding,
            allowed_roles: value.allowedRoles,
            max_integrity: maxIntegrity,
            profile_version: value.profileVersion,
          };
      if (usingCsr && !request.csr_b64) {
        this.setError("a CSR file is required for the CSR key source");
        return;
      }
      const result = await buildLeafTbs({
        parent_b64: parentDerB64,
        algorithm,
        serial_entropy_b64: randomSerialEntropyB64(),
        locale: this.#locale,
        request,
      });
      this.#pending = {
        kind: "shift_leaf",
        tbsB64: result.tbs_b64,
        parentB64: parentDerB64,
        algorithm,
        renderedSummary: result.summary.rendered,
        journalEntry: (serialB64) => ({
          op: "issue_leaf",
          serial_b64: serialB64,
          parent_b64: parentDerB64,
          subject: result.summary.subject,
        }),
      };
      this.#error = undefined;
    } catch (e) {
      this.setError(renderApiError(this.#locale, parseApiError(e)));
      return;
    }
    this.render();
  }

  // --- CRL (D7: a client-side operation of the same core, available at any
  //     CA — root or org_ca — over its own journal history) ----------------

  private renderCrlOperation(): HTMLElement {
    const fingerprint = this.#parentFingerprintHex;
    const lastNumber = fingerprint ? lastCrlNumber(this.#journalLines, fingerprint) : 0;
    const candidates = fingerprint ? revocationCandidates(this.#journalLines, fingerprint) : [];
    const form: CrlFormHandle = buildCrlForm(this.#locale, lastNumber, candidates);
    const algorithmSelect = algorithmSelectWidget();
    const buildBtn = el("button", { type: "button", class: "btn-primary" }, [
      this.t("crl_action_issue"),
    ]);
    buildBtn.addEventListener("click", () => {
      void this.onBuildCrl(form, lastNumber, algorithmSelect.value as SignatureAlgorithmTag);
    });
    return el("section", { class: "section section-operation section-crl" }, [
      form.root,
      field(this.t("field_algorithm"), algorithmSelect),
      buildBtn,
    ]);
  }

  private async onBuildCrl(
    form: CrlFormHandle,
    lastNumber: number,
    algorithm: SignatureAlgorithmTag,
  ): Promise<void> {
    if (!this.#parentDerB64) return;
    const issuerDerB64 = this.#parentDerB64;
    const value = form.getValue();
    if (value.thisUpdate === undefined) {
      this.setError("this_update is required");
      return;
    }
    if (value.crlNumber <= lastNumber) {
      this.setError(
        `crl_number ${value.crlNumber} must be strictly greater than the last issued ${lastNumber}`,
      );
      return;
    }

    try {
      const result = await buildCrlTbs({
        issuer_b64: issuerDerB64,
        algorithm,
        locale: this.#locale,
        request: {
          this_update: value.thisUpdate,
          next_update: value.nextUpdate,
          crl_number: value.crlNumber,
          revoked: value.revoked.map((r) => ({
            serial_b64: hexToBase64(r.serialHex),
            revocation_date: r.revocationDate,
          })),
        },
        last_crl_number: lastNumber,
      });
      this.#pending = {
        kind: "crl",
        tbsB64: result.tbs_b64,
        parentB64: issuerDerB64,
        algorithm,
        renderedSummary: result.summary.rendered,
        journalEntry: () => ({
          op: "issue_crl",
          crl_number: value.crlNumber,
          parent_b64: issuerDerB64,
        }),
      };
      this.#error = undefined;
    } catch (e) {
      this.setError(renderApiError(this.#locale, parseApiError(e)));
      return;
    }
    this.render();
  }

  // --- snapshot ---------------------------------------------------------

  private renderSnapshotSection(): HTMLElement {
    const manualRadio = el("input", {
      type: "radio",
      name: "snapshot-mode",
      value: "manual",
      checked: this.#snapshotMode === "manual" ? "checked" : undefined,
    });
    const fileRadio = el("input", {
      type: "radio",
      name: "snapshot-mode",
      value: "file",
      checked: this.#snapshotMode === "file" ? "checked" : undefined,
    });
    manualRadio.addEventListener("change", () => {
      this.#snapshotMode = "manual";
      this.render();
    });
    fileRadio.addEventListener("change", () => {
      this.#snapshotMode = "file";
      this.render();
    });
    const modeRow = el("div", { class: "snapshot-mode-picker" }, [
      el("label", {}, [manualRadio, this.t("snapshot_mode_manual")]),
      el("label", {}, [fileRadio, this.t("snapshot_mode_file")]),
    ]);

    const modeBody =
      this.#snapshotMode === "manual" ? this.renderSnapshotConstructor() : this.renderSnapshotFilePicker();

    const status = this.#snapshot
      ? el("p", {}, [
          `${this.#snapshot.origin === "signed" ? this.t("snapshot_origin_signed") : this.t("snapshot_origin_manual")} — ${this.t("snapshot_age")}: ${formatAge(this.#snapshot.ageSeconds)}`,
        ])
      : el("p", { class: "hint" }, [this.t("snapshot_none")]);

    return el("section", { class: "section section-snapshot" }, [
      el("h2", {}, [this.t("section_snapshot")]),
      el("p", { class: "hint" }, [this.t("snapshot_file_hint")]),
      modeRow,
      modeBody,
      status,
    ]);
  }

  /**
   * The file-upload path (signed export or a hand-authored manual file).
   * The verify-key field lives here, not in the constructor (`renderSnapshotConstructor`):
   * it only matters for checking a *loaded* file's signature — a snapshot
   * assembled in the constructor is unsigned by construction, so showing a
   * signature-verification key next to it would just be confusing.
   */
  private renderSnapshotFilePicker(): HTMLElement {
    const fileInput = el("input", { type: "file", accept: ".json" });
    fileInput.addEventListener("change", () => {
      void this.onSnapshotFileChosen(fileInput);
    });

    const keyTextarea = el("textarea", { rows: "3", placeholder: '{"kty":"EC","crv":"P-256",...}' });
    const savedKey = loadSnapshotVerifyKey(this.#storage);
    if (savedKey) keyTextarea.value = JSON.stringify(savedKey);
    const saveKeyBtn = el("button", { type: "button" }, [this.t("agent_save")]);
    saveKeyBtn.addEventListener("click", () => {
      try {
        const jwk = JSON.parse(keyTextarea.value) as JsonWebKey;
        saveSnapshotVerifyKey(this.#storage, jwk);
        this.#error = undefined;
      } catch {
        this.setError("invalid JWK");
      }
    });

    return el("div", { class: "snapshot-file-picker" }, [
      fileInput,
      field(this.t("snapshot_verify_key_label"), keyTextarea),
      el("p", { class: "hint" }, [this.t("snapshot_verify_key_hint")]),
      saveKeyBtn,
    ]);
  }

  /**
   * The inventory constructor (spec `issuer-cabinet` — "Сборка инвентаря
   * конструктором"): device/user/role/tag editors and a "build" button that
   * assembles a {@link SnapshotPayload}, runs it through
   * {@link buildManualSnapshot} + {@link acceptSnapshot} — the exact same
   * acceptance path a manual snapshot *file* goes through, so there is only
   * one code path that decides what counts as a valid manual inventory — and
   * a "download" button once one has been built, for reuse in a later
   * session.
   */
  private renderSnapshotConstructor(): HTMLElement {
    const hosts = hostListInput(
      this.t("field_add"),
      this.t("field_remove"),
      this.t("snapshot_host_id_placeholder"),
      this.t("snapshot_host_label_placeholder"),
    );
    const users = stringListInput(this.t("field_add"), this.t("field_remove"));
    const roles = stringListInput(this.t("field_add"), this.t("field_remove"));
    const tags = tagListInput(this.t("field_add"), this.t("field_remove"), []);

    const buildBtn = el("button", { type: "button", class: "btn-primary" }, [
      this.t("snapshot_build_action"),
    ]);
    const downloadBtn = el("button", { type: "button" }, [this.t("snapshot_download_action")]);
    if (this.#snapshot?.origin !== "manual") downloadBtn.classList.add("hidden");
    downloadBtn.addEventListener("click", () => {
      if (!this.#snapshot || this.#snapshot.origin !== "manual") return;
      const file = buildManualSnapshot(this.#snapshot.payload);
      downloadText("inventory-snapshot.json", JSON.stringify(file), "application/json");
    });

    buildBtn.addEventListener("click", () => {
      void (async () => {
        const payload: SnapshotPayload = {
          generated_at: Math.floor(Date.now() / 1000),
          hosts: hosts.getValue(),
          users: users.getValue(),
          roles: roles.getValue(),
          tags: tags.getValue().map(([key, value]) => ({ key, value })),
        };
        const file = buildManualSnapshot(payload);
        const result = await acceptSnapshot(JSON.stringify(file), undefined, Math.floor(Date.now() / 1000));
        if (!result.ok) {
          this.setError(result.rejection.kind === "malformed" ? result.rejection.message : "invalid inventory");
          return;
        }
        this.#snapshot = result.snapshot;
        this.#error = undefined;
        this.render();
      })();
    });

    return el("div", { class: "snapshot-constructor" }, [
      field(this.t("snapshot_hosts_label"), hosts.root),
      field(this.t("snapshot_users_label"), users.root),
      field(this.t("snapshot_roles_label"), roles.root),
      field(this.t("snapshot_tags_label"), tags.root),
      el("div", { class: "snapshot-constructor-actions" }, [buildBtn, downloadBtn]),
    ]);
  }

  private async onSnapshotFileChosen(input: HTMLInputElement): Promise<void> {
    try {
      const text = await readFileAsText(input);
      const jwk = loadSnapshotVerifyKey(this.#storage);
      const result = await acceptSnapshot(text, jwk, Math.floor(Date.now() / 1000));
      if (!result.ok) {
        const message =
          result.rejection.kind === "bad_signature"
            ? this.t("snapshot_rejected_bad_signature")
            : result.rejection.kind === "no_key"
              ? this.t("snapshot_rejected_no_key")
              : result.rejection.message;
        this.setError(message);
        return;
      }
      this.#snapshot = result.snapshot;
      this.#error = undefined;
    } catch (e) {
      this.setError(String(e));
    }
    this.render();
  }

  // --- agent --------------------------------------------------------------

  private agentStatusLabel(status: AgentStatus): string {
    switch (status) {
      case "unknown":
        return this.t("agent_status_unknown");
      case "connecting":
        return this.t("agent_status_connecting");
      case "connected":
        return this.t("agent_status_connected");
      case "error":
        return this.t("agent_status_disconnected");
    }
  }

  /** Update the status indicator element in place, without a full `render()` — a full re-render would drop whatever the operator has typed into an unfinished operation form (design §4). */
  private setAgentStatusIndicator(indicator: HTMLElement, status: AgentStatus): void {
    this.#agentStatus = status;
    indicator.textContent = this.agentStatusLabel(status);
    indicator.className = `agent-status agent-status-${status}`;
  }

  /**
   * The injected settings were handed to us by the same agent that served
   * this page — asking the operator to re-enter (or even see) address/token/
   * key would just be noise. Only the connectivity indicator matters here;
   * {@link autoCheckAgentConnection} keeps it current without a click.
   */
  private renderAgentSectionInjected(): HTMLElement {
    const statusEl = el("span", { class: `agent-status agent-status-${this.#agentStatus}` }, [
      this.agentStatusLabel(this.#agentStatus),
    ]);
    return el("section", { class: "section section-agent section-agent-compact" }, [
      el("h2", { class: "section-heading" }, [this.t("section_agent")]),
      el("div", { class: "agent-actions" }, [statusEl]),
    ]);
  }

  private renderAgentSection(): HTMLElement {
    if (this.#agentInjected) return this.renderAgentSectionInjected();

    const addressInput = el("input", {
      type: "text",
      value: this.#agentSettings?.address ?? "http://127.0.0.1:",
    });
    const tokenInput = el("input", { type: "password", value: this.#agentSettings?.token ?? "" });
    const keyInput = el("input", { type: "text", value: this.#agentSettings?.keyId ?? "" });
    const statusEl = el("span", { class: `agent-status agent-status-${this.#agentStatus}` }, [
      this.agentStatusLabel(this.#agentStatus),
    ]);

    // Guards against the "Подключить" race (L2): editing a field while a
    // `GET /info` check is in flight must not let that check's result
    // clobber the indicator once it resolves — the fields it checked are no
    // longer what's on screen. Every field edit *and* every "Подключить"
    // click bumps this generation counter; a check applies its result only
    // if the generation is still the one it was issued under.
    let connectGeneration = 0;

    const markUnknown = (): void => {
      connectGeneration += 1;
      if (this.#agentStatus !== "unknown") this.setAgentStatusIndicator(statusEl, "unknown");
    };
    addressInput.addEventListener("input", markUnknown);
    tokenInput.addEventListener("input", markUnknown);
    keyInput.addEventListener("input", markUnknown);

    const saveBtn = el("button", { type: "button" }, [this.t("agent_save")]);
    saveBtn.addEventListener("click", () => {
      this.#agentSettings = {
        address: addressInput.value.trim(),
        token: tokenInput.value.trim(),
        keyId: keyInput.value.trim(),
      };
      saveAgentSettings(this.#storage, this.#agentSettings);
    });

    const connectBtn = el("button", { type: "button" }, [this.t("agent_connect")]);
    connectBtn.addEventListener("click", () => {
      const myGeneration = (connectGeneration += 1);
      void (async () => {
        this.#agentSettings = {
          address: addressInput.value.trim(),
          token: tokenInput.value.trim(),
          keyId: keyInput.value.trim(),
        };
        saveAgentSettings(this.#storage, this.#agentSettings);
        this.setAgentStatusIndicator(statusEl, "connecting");
        let outcome: "connected" | "error";
        try {
          await agentInfo(addressInput.value.trim(), tokenInput.value.trim());
          outcome = "connected";
        } catch {
          outcome = "error";
        }
        if (myGeneration !== connectGeneration) return; // stale: fields changed since this check started
        this.setAgentStatusIndicator(statusEl, outcome);
      })();
    });

    const helpBtn = this.helpButton("help_agent_title", [
      el("p", {}, [this.t("help_agent_p1")]),
      el("p", {}, [this.t("help_agent_p2")]),
      el("pre", {}, [AGENT_SERVE_EXAMPLE]),
      el("p", {}, [this.t("help_agent_p3")]),
      el("p", {}, [this.t("help_agent_p4")]),
      el("p", {}, [this.t("help_agent_p5")]),
      el("p", { class: "hint" }, [`${this.t("help_docs_more")}: docs/issuer.md`]),
    ]);

    return el("section", { class: "section section-agent" }, [
      el("h2", { class: "section-heading" }, [this.t("section_agent"), helpBtn]),
      field(this.t("agent_address_label"), addressInput),
      el("p", { class: "hint" }, [this.t("agent_address_hint")]),
      field(this.t("agent_token_label"), tokenInput),
      el("p", { class: "hint" }, [this.t("agent_token_hint")]),
      field(this.t("agent_key_label"), keyInput),
      el("p", { class: "hint" }, [this.t("agent_key_hint")]),
      el("div", { class: "agent-actions" }, [saveBtn, connectBtn, statusEl]),
    ]);
  }

  // --- summary / sign -----------------------------------------------------

  private renderSummarySection(): HTMLElement {
    const pending = this.#pending;
    if (!pending) return el("section", {});

    const confirmBtn = el("button", { type: "button", class: "btn-primary" }, [
      this.t("summary_confirm"),
    ]);
    const cancelBtn = el("button", { type: "button" }, [this.t("summary_cancel")]);
    cancelBtn.addEventListener("click", () => {
      this.#pending = undefined;
      this.render();
    });
    confirmBtn.addEventListener("click", () => {
      void this.onConfirmSign(pending);
    });

    return el("section", { class: "section section-summary" }, [
      el("h2", {}, [this.t("summary_title")]),
      el("pre", {}, [pending.renderedSummary]),
      el("div", { class: "summary-actions" }, [confirmBtn, cancelBtn]),
    ]);
  }

  private async onConfirmSign(pending: PendingOperation): Promise<void> {
    if (!this.#agentSettings) {
      this.setError("configure the signing agent first");
      return;
    }
    try {
      const signature = await agentSign(
        this.#agentSettings.address,
        this.#agentSettings.token,
        this.#agentSettings.keyId,
        pending.tbsB64,
      );
      const assembled = await assembleAndVerify({
        tbs_b64: pending.tbsB64,
        signature: { algorithm: signature.algorithm, bytes_b64: signature.signatureB64 },
        parent_b64: pending.parentB64,
      });
      const filename = `${assembled.kind}-${Date.now()}.pem`;
      downloadText(filename, assembled.cert_pem, "application/x-pem-file");

      const serialB64 = extractSerialB64(assembled.cert_b64);
      const appended = await journalAppend({
        prev_lines: this.#journalLines,
        entry: pending.journalEntry(serialB64),
        now_unix: Math.floor(Date.now() / 1000),
      });
      this.#journalLines = [...this.#journalLines, appended.new_line];

      this.#pending = undefined;
      this.#error = undefined;
    } catch (e) {
      const message = e instanceof AgentError ? e.message : renderApiError(this.#locale, parseApiError(e));
      this.setError(`${this.t("sign_error")}: ${message}`);
      return;
    }
    this.render();
  }

  // --- journal --------------------------------------------------------

  private renderJournalSection(): HTMLElement {
    const loadInput = el("input", { type: "file", accept: ".ndjson,.jsonl,.txt" });
    loadInput.addEventListener("change", () => {
      void (async () => {
        try {
          const text = await readFileAsText(loadInput);
          this.#journalLines = parseJournalFile(text);
          this.#error = undefined;
        } catch (e) {
          this.setError(String(e));
        }
        this.render();
      })();
    });

    const downloadBtn = el("button", { type: "button" }, [this.t("journal_download")]);
    downloadBtn.addEventListener("click", () => {
      downloadText("issuance.ndjson", renderJournalFile(this.#journalLines), "application/x-ndjson");
    });

    const verifyBtn = el("button", { type: "button" }, [this.t("journal_verify")]);
    const statusEl = el("p", { class: "journal-status" });
    verifyBtn.addEventListener("click", () => {
      void (async () => {
        const report = await journalVerify(this.#journalLines);
        statusEl.textContent = renderJournalStatus(this.#locale, report);
      })();
    });

    return el("section", { class: "section section-journal" }, [
      el("h2", {}, [this.t("section_journal")]),
      el("div", { class: "journal-actions" }, [
        field(this.t("journal_load"), loadInput),
        downloadBtn,
        verifyBtn,
      ]),
      statusEl,
    ]);
  }
}

function field(label: string, input: HTMLElement): HTMLElement {
  return el("div", { class: "field" }, [el("label", {}, [label]), input]);
}

function algorithmSelectWidget(): HTMLSelectElement {
  return el(
    "select",
    {},
    ALGORITHMS.map((a) => el("option", { value: a }, [a])),
  );
}

function formatAge(seconds: number): string {
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} d`;
}

/**
 * Recover the serial number's DER `INTEGER` content octets from an assembled
 * certificate, for the journal entry — a minimal walk of the fixed
 * `TBSCertificate` prefix (`SEQUENCE { SEQUENCE { [0] version, INTEGER
 * serialNumber, ... } }`), Base64-encoded. On any parse surprise this falls
 * back to an empty serial rather than throwing — the journal entry is best
 * effort, the certificate itself is already downloaded. Not meaningful for a
 * CRL artifact (no serial); the CRL journal entry never reads this value.
 */
function extractSerialB64(certDerB64: string): string {
  try {
    const der = base64ToBytes(certDerB64);
    let offset = 0;
    const readTlv = (buf: Uint8Array, at: number): { tag: number; content: Uint8Array; next: number } => {
      const tag = buf[at];
      if (tag === undefined) throw new Error("truncated");
      let lenByte = buf[at + 1];
      if (lenByte === undefined) throw new Error("truncated");
      let lenOffset = at + 2;
      let length: number;
      if (lenByte < 0x80) {
        length = lenByte;
      } else {
        const numBytes = lenByte & 0x7f;
        length = 0;
        for (let i = 0; i < numBytes; i += 1) {
          const b = buf[lenOffset + i];
          if (b === undefined) throw new Error("truncated");
          length = length * 256 + b;
        }
        lenOffset += numBytes;
      }
      const content = buf.slice(lenOffset, lenOffset + length);
      return { tag, content, next: lenOffset + length };
    };
    const outer = readTlv(der, offset); // Certificate SEQUENCE
    const tbs = readTlv(outer.content, 0); // TBSCertificate SEQUENCE
    offset = 0;
    const first = readTlv(tbs.content, offset);
    let serialTlv;
    if (first.tag === 0xa0) {
      // version present, skip it
      serialTlv = readTlv(tbs.content, first.next);
    } else {
      serialTlv = first;
    }
    return bytesToBase64(serialTlv.content);
  } catch {
    return "";
  }
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Decode a lowercase-hex serial (the journal's/CLI's format) to standard Base64, for `build_crl_tbs`. */
function hexToBase64(hex: string): string {
  const clean = hex.trim().toLowerCase();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytesToBase64(bytes);
}
