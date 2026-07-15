import test from "node:test";
import assert from "node:assert/strict";

import { parseJournalFile, renderJournalFile, renderJournalStatus } from "./journal.ts";

test("parseJournalFile/renderJournalFile round-trip non-empty lines", () => {
  const text = 'line-one\nline-two\n';
  const lines = parseJournalFile(text);
  assert.deepEqual(lines, ["line-one", "line-two"]);
  assert.equal(renderJournalFile(lines), text);
});

test("parseJournalFile drops blank lines", () => {
  assert.deepEqual(parseJournalFile("a\n\n\nb\n"), ["a", "b"]);
});

test("renderJournalFile of an empty journal is an empty string", () => {
  assert.equal(renderJournalFile([]), "");
});

test("renderJournalStatus renders each status in both locales", () => {
  assert.match(
    renderJournalStatus("en", { status: "intact", entry_count: 3 }),
    /intact, fully signed — 3 entries/,
  );
  assert.match(
    renderJournalStatus("ru", { status: "intact", entry_count: 3 }),
    /цела, полностью подписана — 3 записей/,
  );
  assert.match(
    renderJournalStatus("en", {
      status: "intact_unsigned_tail",
      entry_count: 5,
      unsigned_from_seq: 2,
    }),
    /unsigned tail from seq 2 — 5 entries/,
  );
  assert.match(
    renderJournalStatus("en", { status: "broken", entry_count: 5, position: 4 }),
    /broken at position 4 — 5 entries/,
  );
});
