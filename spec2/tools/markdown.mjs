// Разбор тела markdown-файла spec2: маскирование зон кода/цитат, извлечение
// навигационных ссылок `[[context.id]]`, нормативных операторов и границ предложений.

/**
 * Маскирует БЛОЧНЫЕ зоны — блоки кода (``` / ~~~) и цитаты (`>`) — целыми
 * строками, но НЕ трогает инлайн-код (`` `...` ``) внутри оставшихся строк.
 * Нужна отдельно от {@link maskZones}: синтаксис Evidence/Outcomes/Partition/
 * Combinations сам использует одиночные обратные кавычки для якорей и имён
 * исходов (`` `code:путь#Символ` ``), поэтому эти четыре конструкции обязаны
 * читаться из блочно-, а не полностью замаскированного текста — иначе
 * легитимный якорь стирается вместе с иллюстрацией (конституция §9 запрещает
 * читать смысл из блока кода/цитаты, но не запрещает инлайн-код внутри
 * собственного синтаксиса этих строк).
 * @param {string[]} lines
 * @returns {string[]}
 */
export function maskBlockZones(lines) {
  const masked = [];
  let inFence = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^(```+|~~~+)/.test(trimmed)) {
      inFence = !inFence;
      masked.push('');
      continue;
    }
    if (inFence) {
      masked.push('');
      continue;
    }
    if (trimmed.startsWith('>')) {
      masked.push('');
      continue;
    }
    masked.push(line);
  }
  return masked;
}

/**
 * Маскирует зоны, из которых конституция §«зоны markdown» запрещает извлекать
 * нормы и ссылки: блоки кода (``` / ~~~), инлайн-код (`...`) и цитаты (`>`).
 * Возвращает массив строк той же длины и той же построчной разбивки — символы
 * замаскированных зон заменены пробелами, переносы строк сохранены, поэтому
 * номера строк не съезжают.
 * @param {string[]} lines
 * @returns {string[]}
 */
export function maskZones(lines) {
  return maskBlockZones(lines).map((line) => line.replace(/`[^`]*`/g, (m) => ' '.repeat(m.length)));
}

/**
 * @typedef {{ ref: string, wordform: string|null, line: number, index: number }} LinkOccurrence
 */

const LINK_RE = /\[\[([^\]|:]+)(?:\|([^\]]+))?\]\]/g;

/**
 * Находит ссылки `[[context.id]]` / `[[context.id|словоформа]]`.
 * @param {string[]} maskedLines
 * @param {number} startLineNo номер первой строки массива в исходном файле (1-based)
 * @returns {LinkOccurrence[]}
 */
export function findLinks(maskedLines, startLineNo) {
  /** @type {LinkOccurrence[]} */
  const out = [];
  for (let i = 0; i < maskedLines.length; i++) {
    const line = maskedLines[i];
    LINK_RE.lastIndex = 0;
    let m;
    while ((m = LINK_RE.exec(line))) {
      out.push({
        ref: m[1].trim(),
        wordform: m[2] ? m[2].trim() : null,
        line: startLineNo + i,
        index: m.index,
      });
    }
  }
  return out;
}

/**
 * То же, что {@link findLinks}, но по цельному тексту (без разбивки на строки) —
 * нужно для анализа ссылок внутри границ одного предложения.
 * @param {string} text
 * @returns {Omit<LinkOccurrence, 'line'>[]}
 */
export function findLinksInText(text) {
  const out = [];
  LINK_RE.lastIndex = 0;
  let m;
  while ((m = LINK_RE.exec(text))) {
    out.push({ ref: m[1].trim(), wordform: m[2] ? m[2].trim() : null, index: m.index });
  }
  return out;
}

/**
 * Строит функцию перевода абсолютного смещения в тексте (со склеенными `\n`)
 * в номер строки исходного файла.
 * @param {string} text
 * @param {number} startLineNo
 * @returns {(offset: number) => number}
 */
export function buildOffsetToLine(text, startLineNo) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return (offset) => {
    let lo = 0, hi = starts.length - 1, ans = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (starts[mid] <= offset) { ans = mid; lo = mid + 1; } else hi = mid - 1;
    }
    return startLineNo + ans;
  };
}

/**
 * @typedef {{ start: number, end: number }} SentenceSpan
 */

/**
 * Разбивает текст на предложения по правилу конституции: граница — `. ` (точка
 * с пробелом/переносом) либо пустая строка между абзацами (`\n\n`).
 * @param {string} text
 * @returns {SentenceSpan[]}
 */
export function splitSentences(text) {
  /** @type {SentenceSpan[]} */
  const sentences = [];
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const paraBreak = /^\n[ \t]*\n+/.exec(text.slice(i));
    if (paraBreak) {
      if (i > start) sentences.push({ start, end: i });
      i += paraBreak[0].length;
      start = i;
      continue;
    }
    if (text[i] === '.' && (text[i + 1] === ' ' || text[i + 1] === '\n' || i + 1 === text.length)) {
      const end = i + 1;
      sentences.push({ start, end });
      let j = end;
      while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++;
      i = j;
      start = j;
      continue;
    }
    i++;
  }
  if (start < text.length) sentences.push({ start, end: text.length });
  return sentences.filter((s) => text.slice(s.start, s.end).trim() !== '');
}

// MUST NOT проверяется первым — иначе матч на MUST "съедает" начало MUST NOT.
// Между MUST и NOT — произвольные пробельные символы, включая перенос строки:
// предложения склеиваются через "\n" (см. splitSentences), и текст спеки
// переносится по ширине колонки, так что "MUST\nNOT" — обычный случай, а не
// исключение. Один жёсткий пробел между словами инвертировал бы запрет в
// обязательство.
const OPERATOR_RE = /\bMUST\s+NOT\b|\bMUST\b|\bMAY\b/g;

/**
 * Находит нормативные операторы (латиница) в тексте предложения.
 * @param {string} sentenceText
 * @returns {{ op: string, index: number }[]}
 */
export function findOperators(sentenceText) {
  const out = [];
  OPERATOR_RE.lastIndex = 0;
  let m;
  while ((m = OPERATOR_RE.exec(sentenceText))) {
    out.push({ op: m[0], index: m.index });
  }
  return out;
}

// Русские операторы, запрещённые конституцией §1: все формы ДОЛЖЕН/ОБЯЗАН,
// ЗАПРЕЩЕНО/ЗАПРЕЩАЕТСЯ/ЗАПРЕЩЁН/НЕЛЬЗЯ, МОЖЕТ/МОГУТ/МОЖНО, плюс английские
// SHALL/REQUIRED/SHOULD(NOT). Список раньше был закрыт коротким перечислением
// (REVIEW.md M2) — ЗАПРЕЩАЕТСЯ, ЗАПРЕЩЁН, НЕЛЬЗЯ, МОГУТ, МОЖНО, SHALL,
// REQUIRED, SHOULD NOT не ловились вовсе. "SHOULD\s+NOT" обязан стоять ПЕРЕД
// "SHOULD" в альтернации — на общей стартовой позиции регэксп берёт первую
// подошедшую альтернативу, а не самую длинную (тот же порядок, что у "MUST
// NOT" перед "MUST" в {@link OPERATOR_RE}).
// Границы слова считаются вручную, т.к. \b в JS не видит кириллицу как
// "словесный" символ; класс границы включает и цифры/подчёркивание (иначе
// "ДОЛЖЕН1" ложно засчитывался бы отдельным словом), и диапазон комбинирующих
// диакритических знаков U+0300–U+036F — на случай, если строка не приведена
// к NFC и "й"/"ё" пришли в декомпозированной форме (гласная + отдельный
// комбинирующий знак), тогда символ ПОСЛЕ формально видимого слова на самом
// деле его продолжает.
const WORD_BOUNDARY_CLASS = 'A-Za-zА-Яа-яЁё0-9_\\u0300-\\u036f';
const RU_OPERATOR_RE = new RegExp(
  `(?<![${WORD_BOUNDARY_CLASS}])(ДОЛЖЕН|ДОЛЖНА|ДОЛЖНО|ДОЛЖНЫ|ОБЯЗАН[А-Я]*|ЗАПРЕЩЕНО|ЗАПРЕЩАЕТСЯ|ЗАПРЕЩЁН[А-Я]*|НЕЛЬЗЯ|МОЖЕТ|МОГУТ|МОЖНО|SHALL|REQUIRED|SHOULD\\s+NOT|SHOULD)(?![${WORD_BOUNDARY_CLASS}])`,
  'g',
);

/**
 * Находит запрещённые русские операторы (и их английские аналоги вне MUST/MAY)
 * в замаскированных строках. Каждая строка приводится к NFC перед поиском —
 * декомпозированные "й"/"ё" (гласная + отдельный комбинирующий знак) иначе
 * проходят мимо и лукахеда границы, и самого списка слов (REVIEW.md M2).
 * @param {string[]} maskedLines
 * @param {number} startLineNo
 * @returns {{ line: number, match: string }[]}
 */
export function findRuOperators(maskedLines, startLineNo) {
  const out = [];
  for (let i = 0; i < maskedLines.length; i++) {
    const line = maskedLines[i].normalize('NFC');
    RU_OPERATOR_RE.lastIndex = 0;
    let m;
    while ((m = RU_OPERATOR_RE.exec(line))) {
      out.push({ line: startLineNo + i, match: m[0] });
    }
  }
  return out;
}

/**
 * Находит заголовки markdown (`#`..`######`) с их уровнем и текстом.
 * @param {string[]} maskedLines
 * @param {number} startLineNo
 * @returns {{ level: number, text: string, line: number }[]}
 */
export function findHeadings(maskedLines, startLineNo) {
  const out = [];
  for (let i = 0; i < maskedLines.length; i++) {
    const m = /^(#{1,6})\s+(.*)$/.exec(maskedLines[i]);
    if (m) out.push({ level: m[1].length, text: m[2].trim(), line: startLineNo + i });
  }
  return out;
}
