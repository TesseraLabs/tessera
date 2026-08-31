// Реестр адаптеров языков для `spec.mjs outcomes` (задача команды, п.5):
// каждый адаптер знает, как извлечь исходы возвращаемого типа и то, что
// уходит мимо него (throw/raise), из исходника своего языка. Интерфейс общий,
// чтобы следующий язык добавлялся файлом, а не веткой if/else в spec.mjs.

import rustAdapter from './rust.mjs';
import typescriptAdapter from './typescript.mjs';
import csharpAdapter from './csharp.mjs';
import pythonAdapter from './python.mjs';

/**
 * @typedef {{
 *   declared: string[], escaping: string[],
 *   confidence: 'exact'|'syntactic'|'shallow', unresolved: string[]
 * }} OutcomeExtraction
 * @typedef {{ language: string, extensions: string[],
 *   extractOutcomes: (source: string, symbol: string) => OutcomeExtraction|null }} LanguageAdapter
 */

/** @type {LanguageAdapter[]} */
const ADAPTERS = [rustAdapter, typescriptAdapter, csharpAdapter, pythonAdapter];

/**
 * Находит адаптер по расширению файла (`.rs` → rust, `.ts`/`.tsx`/`.js`/…
 * → typescript, `.cs` → csharp, `.py` → python).
 * @param {string} filePath
 * @returns {LanguageAdapter|null}
 */
export function adapterForFile(filePath) {
  const ext = filePath.slice(filePath.lastIndexOf('.'));
  return ADAPTERS.find((a) => a.extensions.includes(ext)) || null;
}

/**
 * Список поддерживаемых расширений — для понятного сообщения об ошибке,
 * когда язык якоря неизвестен инструменту.
 * @returns {string[]}
 */
export function supportedExtensions() {
  return ADAPTERS.flatMap((a) => a.extensions);
}
