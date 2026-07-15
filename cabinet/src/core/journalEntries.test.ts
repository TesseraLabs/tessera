import test from "node:test";
import assert from "node:assert/strict";

import { lastCrlNumber, parseJournalLines, revocationCandidates } from "./journalEntries.ts";

const CA_A = "aa".repeat(32);
const CA_B = "bb".repeat(32);

function line(obj: Record<string, unknown>): string {
  return JSON.stringify(obj);
}

const lines = [
  line({ seq: 0, prev_hash: "0".repeat(64), ts: 1, op: "issue_ca", serial: "01", parent: CA_A, subject: "CN=root" }),
  line({ seq: 1, prev_hash: "1".repeat(64), ts: 2, op: "issue_leaf", serial: "02", parent: CA_A, subject: "CN=ivanov" }),
  line({ seq: 2, prev_hash: "2".repeat(64), ts: 3, op: "issue_leaf", serial: "03", parent: CA_B, subject: "CN=petrov" }),
  line({ seq: 3, prev_hash: "3".repeat(64), ts: 4, op: "issue_crl", crl_number: 1, parent: CA_A }),
  line({ seq: 4, prev_hash: "4".repeat(64), ts: 5, op: "issue_crl", crl_number: 2, parent: CA_A }),
  line({ seq: 5, prev_hash: "5".repeat(64), ts: 6, op: "head_signature", algorithm: "ecdsa-sha256", signature: "AA==" }),
  "not json at all",
];

test("parseJournalLines extracts issued and CRL entries, skipping unrelated/malformed lines", () => {
  const { issued, crls } = parseJournalLines(lines);
  assert.equal(issued.length, 3);
  assert.equal(crls.length, 2);
});

test("revocationCandidates scopes to the CA's own fingerprint, newest first", () => {
  const candidates = revocationCandidates(lines, CA_A);
  assert.deepEqual(
    candidates.map((c) => c.serialHex),
    ["02", "01"],
  );
  assert.deepEqual(
    revocationCandidates(lines, CA_B).map((c) => c.serialHex),
    ["03"],
  );
});

test("lastCrlNumber returns the highest crl_number for the matching CA, 0 if none", () => {
  assert.equal(lastCrlNumber(lines, CA_A), 2);
  assert.equal(lastCrlNumber(lines, CA_B), 0);
  assert.equal(lastCrlNumber([], CA_A), 0);
});
