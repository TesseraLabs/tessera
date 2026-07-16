import test from "node:test";
import assert from "node:assert/strict";

import { filterStringListValues } from "./widgets.ts";

// `suggestingStringListInput` wraps a native `<input list>` combobox — its
// DOM can't be driven headlessly under `node:test` (no `document`), so it is
// exercised by hand like the rest of `ui/*`. What *is* pure and worth
// testing is the value-filtering it shares with `stringListInput`: free
// input (not in the datalist) must survive, blanks must not.
test("filterStringListValues trims and drops empty entries, preserving free-text input", () => {
  assert.deepEqual(
    filterStringListValues(["  sha256:aaaa  ", "", "  ", "not-in-any-datalist"]),
    ["sha256:aaaa", "not-in-any-datalist"],
  );
});

test("filterStringListValues on an all-blank list returns empty", () => {
  assert.deepEqual(filterStringListValues(["", "   ", "\t"]), []);
});

test("filterStringListValues is a no-op on already-clean values", () => {
  assert.deepEqual(filterStringListValues(["ivanov", "petrov"]), ["ivanov", "petrov"]);
});
