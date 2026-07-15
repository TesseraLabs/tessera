import test from "node:test";
import assert from "node:assert/strict";

import { startupErrorText } from "./startupError.ts";

test("startupErrorText localizes the title/detail and embeds an Error's message", () => {
  const en = startupErrorText("en", new Error("CSP violation: wasm-unsafe-eval required"));
  assert.equal(en.title, "The cabinet failed to start");
  assert.match(en.detail, /CSP violation: wasm-unsafe-eval required/);

  const ru = startupErrorText("ru", new Error("boom"));
  assert.equal(ru.title, "Кабинет не смог инициализироваться");
  assert.match(ru.detail, /boom/);
});

test("startupErrorText stringifies a non-Error rejection", () => {
  const text = startupErrorText("en", "plain string failure");
  assert.match(text.detail, /plain string failure/);

  const fromObject = startupErrorText("en", { code: 42 });
  assert.match(fromObject.detail, /\[object Object\]|42/);
});
