// The browser-side half of the issuance journal (spec `issuer-cabinet` +
// `issuance-journal`; design D8). The hash-chain logic itself lives in the
// WASM core (`journal_append`/`journal_verify`); this module only holds the
// journal as the cabinet actually stores it — an in-memory list of NDJSON
// lines loaded from, and saved back to, a file the operator picks — plus the
// pure text (de)serialisation around that file.

import type { Locale } from "../i18n/locale.ts";
import { t } from "../i18n/locale.ts";
import type { JournalVerifyResponse } from "../types.ts";

/** Parse a loaded journal file's text into lines, dropping blank trailing lines. */
export function parseJournalFile(text: string): string[] {
  return text.split("\n").filter((line) => line.trim().length > 0);
}

/** Render journal lines back to the NDJSON file text (one line each, trailing newline). */
export function renderJournalFile(lines: string[]): string {
  return lines.length === 0 ? "" : lines.join("\n") + "\n";
}

/** Render a `journal_verify` report as one human-readable status line. */
export function renderJournalStatus(locale: Locale, report: JournalVerifyResponse): string {
  const countLabel = t(locale, "journal_entry_count");
  const count = `${report.entry_count} ${countLabel}`;
  switch (report.status) {
    case "intact":
      return `${t(locale, "journal_status_intact")} — ${count}`;
    case "intact_unsigned_tail":
      return `${t(locale, "journal_status_intact_unsigned_tail")} ${report.unsigned_from_seq ?? "?"} — ${count}`;
    case "broken":
      return `${t(locale, "journal_status_broken")} ${report.position ?? "?"} — ${count}`;
    default:
      return `${t(locale, "journal_status_unknown")} — ${count}`;
  }
}
