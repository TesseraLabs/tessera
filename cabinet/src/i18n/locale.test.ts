import test from "node:test";
import assert from "node:assert/strict";

import { domainDefaultLocale, localeFromLanguageTag, resolveLocale, t } from "./locale.ts";

test("t looks up the same key in both locales", () => {
  assert.equal(t("en", "app_title"), "Tessera Issuer Cabinet");
  assert.equal(t("ru", "app_title"), "Кабинет выпуска Tessera");
});

test("localeFromLanguageTag matches ru by prefix, case-insensitively", () => {
  assert.equal(localeFromLanguageTag("ru"), "ru");
  assert.equal(localeFromLanguageTag("ru-RU"), "ru");
  assert.equal(localeFromLanguageTag("RU"), "ru");
  assert.equal(localeFromLanguageTag("en-US"), undefined);
  assert.equal(localeFromLanguageTag(undefined), undefined);
  assert.equal(localeFromLanguageTag(null), undefined);
  assert.equal(localeFromLanguageTag(""), undefined);
});

test("domainDefaultLocale picks ru only for .ru hosts", () => {
  assert.equal(domainDefaultLocale("issuer.tessera-access.ru"), "ru");
  assert.equal(domainDefaultLocale("ISSUER.TESSERA-ACCESS.RU"), "ru");
  assert.equal(domainDefaultLocale("issuer.tessera-access.com"), undefined);
  assert.equal(domainDefaultLocale("localhost"), undefined);
});

test("resolveLocale priority: explicit > domain > browser > en fallback", () => {
  assert.equal(
    resolveLocale({ explicit: "en", hostname: "issuer.tessera-access.ru", browserLanguage: "ru" }),
    "en",
    "explicit choice wins over domain and browser",
  );
  assert.equal(
    resolveLocale({ hostname: "issuer.tessera-access.ru", browserLanguage: "en" }),
    "ru",
    "domain default wins over browser language",
  );
  assert.equal(
    resolveLocale({ hostname: "issuer.tessera-access.com", browserLanguage: "ru-RU" }),
    "ru",
    "browser language used when domain has no default",
  );
  assert.equal(
    resolveLocale({ hostname: "issuer.tessera-access.com", browserLanguage: "fr" }),
    "en",
    "unrecognised browser language falls back to English",
  );
  assert.equal(
    resolveLocale({ hostname: "localhost", browserLanguage: undefined }),
    "en",
    "self-hosted with no signal falls back to English",
  );
});
