// Общие разборщики для адаптеров outcomes (C-подобный синтаксис: TS/JS/C#).
// Rust держит свой сканер в rust.mjs — там кавычка `'` неоднозначна (лайфтайм
// против char-литерала), и смешивать эту логику с общей веткой не стоит.

/**
 * @typedef {{
 *   declared: string[],
 *   escaping: string[],
 *   confidence: 'exact'|'syntactic'|'shallow',
 *   unresolved: string[]
 * }} OutcomeExtraction
 */

/**
 * Вырезает тело `{ ... }`, начиная с символа сразу после открывающей `{`,
 * до соответствующей закрывающей, с учётом вложенных `{}`, `//`- и `/* *\/`-
 * комментариев, строк в `"`/`'` и (опционально) шаблонных строк в `` ` ``.
 * @param {string} source
 * @param {number} braceStart индекс открывающей `{`
 * @param {{ templateLiterals?: boolean }} [opts]
 * @returns {{ body: string, end: number }|null} `end` — индекс закрывающей `}`
 */
export function extractBalancedBraces(source, braceStart, opts = {}) {
  const { templateLiterals = false } = opts;
  let depth = 1;
  let j = braceStart + 1;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;
  let stringChar = null;
  let inTemplate = false;
  const chars = [];
  while (j < source.length) {
    const c = source[j];
    const c2 = source[j + 1];

    if (inLineComment) { if (c === '\n') inLineComment = false; chars.push(c); j++; continue; }
    if (inBlockComment) {
      if (c === '*' && c2 === '/') { inBlockComment = false; chars.push(c, c2); j += 2; continue; }
      chars.push(c); j++; continue;
    }
    if (inString) {
      chars.push(c);
      if (c === '\\') { chars.push(c2 ?? ''); j += 2; continue; }
      if (c === stringChar) inString = false;
      j++; continue;
    }
    if (inTemplate) {
      chars.push(c);
      if (c === '\\') { chars.push(c2 ?? ''); j += 2; continue; }
      if (c === '`') inTemplate = false;
      j++; continue;
    }
    if (c === '/' && c2 === '/') { inLineComment = true; chars.push(c, c2); j += 2; continue; }
    if (c === '/' && c2 === '*') { inBlockComment = true; chars.push(c, c2); j += 2; continue; }
    if (c === '"' || c === "'") { inString = true; stringChar = c; chars.push(c); j++; continue; }
    if (templateLiterals && c === '`') { inTemplate = true; chars.push(c); j++; continue; }
    if (c === '{') { depth++; chars.push(c); j++; continue; }
    if (c === '}') {
      depth--;
      if (depth === 0) return { body: chars.join(''), end: j };
      chars.push(c); j++; continue;
    }
    chars.push(c); j++;
  }
  return null; // скобка не закрылась
}

/**
 * Ищет первую верхнеуровневую границу `stopChar` начиная с `from`, учитывая
 * вложенность `(){}[]<>` и строки. Используется, чтобы найти конец
 * `type X = ...;` или заголовка функции, не заходя внутрь generic-параметров
 * и вложенных литералов объектов.
 * @param {string} source
 * @param {number} from
 * @param {string} stopChar
 * @returns {number} индекс `stopChar`, либо -1
 */
export function findTopLevelChar(source, from, stopChar) {
  let depth = 0;
  let inString = false;
  let stringChar = null;
  for (let j = from; j < source.length; j++) {
    const c = source[j];
    if (inString) {
      if (c === '\\') { j++; continue; }
      if (c === stringChar) inString = false;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inString = true; stringChar = c; continue; }
    if (c === '(' || c === '{' || c === '[' || c === '<') { depth++; continue; }
    if (c === ')' || c === '}' || c === ']' || c === '>') { depth = Math.max(0, depth - 1); continue; }
    if (depth === 0 && c === stopChar) return j;
  }
  return -1;
}

/**
 * Разбивает текст по верхнеуровневому разделителю (не заходя внутрь
 * `(){}[]<>` и строк). Общий инструмент для union-типов (`|`), списков
 * членов enum/параметров (`,`) и т.п.
 * @param {string} text
 * @param {string} sep односимвольный разделитель
 * @returns {string[]}
 */
export function splitTopLevel(text, sep) {
  const parts = [];
  let cur = '';
  let depth = 0;
  let inString = false;
  let stringChar = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      cur += c;
      if (c === '\\') { cur += text[i + 1] ?? ''; i++; continue; }
      if (c === stringChar) inString = false;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inString = true; stringChar = c; cur += c; continue; }
    if (c === '(' || c === '{' || c === '[' || c === '<') { depth++; cur += c; continue; }
    if (c === ')' || c === '}' || c === ']' || c === '>') { depth--; cur += c; continue; }
    if (c === sep && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim() !== '') parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/**
 * Заменяет содержимое `//`- и `/* *\/`-комментариев и строковых/символьных
 * литералов на пробелы той же длины (переносы строк сохраняются). Индексы
 * структурных символов (скобки, `;`, ключевые слова) не сдвигаются — по
 * результату можно безопасно искать заголовки объявлений регэкспами, не
 * рискуя зацепить текст внутри доккомментария (например, `<...>` в XML-доке
 * C#) как часть сигнатуры. Извлекать сами данные (тела, строковые значения)
 * нужно по-прежнему из оригинального `source` при тех же индексах.
 * @param {string} source
 * @returns {string}
 */
export function blankNonCode(source) {
  let out = '';
  let i = 0;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;
  let stringChar = null;
  while (i < source.length) {
    const c = source[i];
    const c2 = source[i + 1];
    if (inLineComment) {
      out += c === '\n' ? '\n' : ' ';
      if (c === '\n') inLineComment = false;
      i++; continue;
    }
    if (inBlockComment) {
      if (c === '*' && c2 === '/') { out += '  '; inBlockComment = false; i += 2; continue; }
      out += c === '\n' ? '\n' : ' ';
      i++; continue;
    }
    if (inString) {
      if (c === '\\') { out += '  '; i += 2; continue; }
      if (c === stringChar) { out += ' '; inString = false; i++; continue; }
      out += c === '\n' ? '\n' : ' ';
      i++; continue;
    }
    if (c === '/' && c2 === '/') { inLineComment = true; out += '  '; i += 2; continue; }
    if (c === '/' && c2 === '*') { inBlockComment = true; out += '  '; i += 2; continue; }
    if (c === '"' || c === "'") { inString = true; stringChar = c; out += ' '; i++; continue; }
    out += c; i++;
  }
  return out;
}

/**
 * Разбивает текст union-типа (`'a' | 'b' | C`) по верхнеуровневым `|`.
 * @param {string} text
 * @returns {string[]}
 */
export function splitTopLevelUnion(text) {
  return splitTopLevel(text, '|');
}

/**
 * Экранирует спецсимволы RegExp в имени символа перед подстановкой в шаблон
 * поиска объявления (REVIEW.md M15). Имя символа берётся из якоря
 * `code:путь#Символ`, который пишет автор спеки руками — символ с `(`, `+`,
 * `[`, `*` даёт либо `SyntaxError` при построении `RegExp` (падение
 * `spec.mjs outcomes` без обработки), либо тихое несовпадение из-за того,
 * что символ читается как часть регэкспа, а не как буквальная строка.
 * @param {string} symbol
 * @returns {string}
 */
export function escapeRegExp(symbol) {
  return String(symbol).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
