// TypeScript/JavaScript-адаптер для `spec.mjs outcomes` (конституция §10).
// Обслуживает `.ts`/`.tsx` (полностью — с типами) и `.js`/`.mjs`/`.cjs`/`.jsx`
// (только escaping-часть: без типов Declared разобрать нечем).

import { extractBalancedBraces, splitTopLevel, splitTopLevelUnion, blankNonCode, escapeRegExp } from './shared.mjs';

/**
 * Находит начало тела `enum X { A, B = 'b', ... }` и возвращает индекс `{`,
 * либо -1, если такого enum нет. Поиск идёт по коду с забланкованными
 * комментариями/строками (`blankNonCode`), а не по сырому `source`: иначе
 * закомментированное объявление того же имени совпадает раньше настоящего,
 * и адаптер выдаёт confidence:"exact" по несуществующему коду (C6). Индексы
 * blankNonCode совпадают с source посимвольно, поэтому `{` ищем в source по
 * найденному индексу — тело извлекается из настоящего кода, не из бланка.
 * @param {string} source
 * @param {string} name
 * @returns {number}
 */
function findEnumBraceStart(source, name) {
  const re = new RegExp(`(?:export\\s+)?(?:declare\\s+)?(?:const\\s+)?enum\\s+${escapeRegExp(name)}\\b`);
  const m = re.exec(blankNonCode(source));
  if (!m) return -1;
  return source.indexOf('{', m.index);
}

/**
 * Извлекает имена членов `enum X { A, B = 1, C = 'c' }`.
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
function extractEnumMembers(source, name) {
  const braceStart = findEnumBraceStart(source, name);
  if (braceStart === -1) return null;
  const res = extractBalancedBraces(source, braceStart);
  if (!res) return null;
  const nameRe = /^\s*([A-Za-z_$][A-Za-z0-9_$]*)/;
  return splitTopLevel(res.body, ',')
    .map((part) => nameRe.exec(part))
    .filter(Boolean)
    .map((m) => m[1]);
}

/**
 * Находит `(?:export )?type <name> = <rhs>;` и возвращает `<rhs>` (текст до
 * верхнеуровневой `;`), либо null, если такого алиаса нет.
 * Поиск заголовка идёт по забланкованному коду (см. {@link findEnumBraceStart})
 * — закомментированный алиас не должен затмевать настоящий (C6).
 * @param {string} source
 * @param {string} name
 * @returns {string|null}
 */
function extractTypeAliasRhs(source, name) {
  const re = new RegExp(`(?:export\\s+)?type\\s+${escapeRegExp(name)}\\s*(?:<[^={]*>)?\\s*=`);
  const m = re.exec(blankNonCode(source));
  if (!m) return null;
  const eqIdx = source.indexOf('=', m.index + m[0].length - 1);
  // Верхнеуровневая `;`, считая вложенность через тот же скан, что и в
  // findTopLevelChar, но нам достаточно искать вручную — переиспользуем
  // extractBalancedBraces было бы избыточно, тип может не иметь `{}` вовсе.
  let depth = 0;
  for (let j = eqIdx + 1; j < source.length; j++) {
    const c = source[j];
    if (c === '(' || c === '{' || c === '[' || c === '<') depth++;
    else if (c === ')' || c === '}' || c === ']' || c === '>') depth = Math.max(0, depth - 1);
    else if (c === ';' && depth === 0) return source.slice(eqIdx + 1, j);
  }
  return null;
}

const KIND_FIELD_RE = /\b(?:kind|type)\s*:\s*(['"])([^'"]*)\1/;

/**
 * Разбирает один член union-типа: строковый литерал, размеченный объект
 * (по полю `kind`/`type`) или ссылка на другой именованный тип.
 * @param {string} source файл целиком (для рекурсивного разрешения ссылок)
 * @param {string} part
 * @param {Set<string>} visited защита от циклов при рекурсии по алиасам
 * @returns {{ values: string[], unresolved: string[] }}
 */
function resolveUnionMember(source, part, visited) {
  const stringLit = /^(['"])([\s\S]*)\1$/.exec(part);
  if (stringLit) return { values: [stringLit[2]], unresolved: [] };

  if (part.startsWith('{')) {
    const kindMatch = KIND_FIELD_RE.exec(part);
    if (kindMatch) return { values: [kindMatch[2]], unresolved: [] };
    return { values: [], unresolved: [`форма union-варианта без поля kind/type: ${part.slice(0, 40)}`] };
  }

  const identMatch = /^([A-Za-z_$][A-Za-z0-9_$.]*)$/.exec(part);
  if (identMatch) {
    const resolved = resolveTypeByName(source, identMatch[1], visited);
    if (resolved) return resolved;
    return { values: [], unresolved: [`union-член "${part}" не разобран (внешний или неизвестный тип)`] };
  }

  return { values: [], unresolved: [`union-член не разобран: ${part.slice(0, 40)}`] };
}

/**
 * Разрешает union-текст (`'a' | 'b' | C`) в плоский список значений,
 * рекурсивно разворачивая ссылки на другие enum/type-алиасы того же файла.
 * @param {string} source
 * @param {string} text
 * @param {Set<string>} visited
 * @returns {{ values: string[], unresolved: string[] }}
 */
function resolveUnionText(source, text, visited) {
  const values = [];
  const unresolved = [];
  for (const part of splitTopLevelUnion(text)) {
    const r = resolveUnionMember(source, part, visited);
    values.push(...r.values);
    unresolved.push(...r.unresolved);
  }
  return { values, unresolved };
}

/**
 * Разрешает именованный тип `name` в плоский список значений-исходов:
 * enum → его члены; type-алиас → развёрнутый union. `null`, если тип не
 * найден в файле (внешний импорт, встроенный тип и т.п.).
 * @param {string} source
 * @param {string} name
 * @param {Set<string>} visited
 * @returns {{ values: string[], unresolved: string[] }|null}
 */
function resolveTypeByName(source, name, visited) {
  if (visited.has(name)) return null; // разорвать цикл — не бесконечный «unresolved»
  visited.add(name);

  const enumMembers = extractEnumMembers(source, name);
  if (enumMembers) return { values: enumMembers, unresolved: [] };

  const rhs = extractTypeAliasRhs(source, name);
  if (rhs !== null) return resolveUnionText(source, rhs, visited);

  return null;
}

/**
 * Находит заголовок функции/метода/стрелочной функции с именем `symbol` и
 * возвращает индекс открывающей `{` тела, либо -1. Пробует по очереди:
 * `function symbol(...)`, `const symbol = (...) =>`, метод `symbol(...) {`.
 * Заголовок ищется по забланкованному коду (см. {@link findEnumBraceStart}):
 * иначе закомментированное объявление совпадает раньше настоящего, и тело
 * функции, которое пойдёт на анализ, окажется чужим либо не найдётся вовсе
 * (C6). Тело по найденному индексу извлекается уже из настоящего `source`.
 * @param {string} source
 * @param {string} symbol
 * @returns {number}
 */
function findFunctionBraceStart(source, symbol) {
  const blanked = blankNonCode(source);
  const patterns = [
    new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+${escapeRegExp(symbol)}\\s*(?:<[^(]*>)?\\s*\\(`),
    new RegExp(`(?:export\\s+)?const\\s+${escapeRegExp(symbol)}\\s*(?::[^=]+)?=\\s*(?:async\\s*)?\\(`),
    new RegExp(`(?:public\\s+|private\\s+|protected\\s+|static\\s+|async\\s+|readonly\\s+)*${escapeRegExp(symbol)}\\s*(?:<[^(]*>)?\\s*\\(`),
  ];
  for (const re of patterns) {
    const m = re.exec(blanked);
    if (!m) continue;
    const parenStart = source.indexOf('(', m.index);
    let depth = 1;
    let j = parenStart + 1;
    while (j < source.length && depth > 0) {
      if (source[j] === '(') depth++;
      else if (source[j] === ')') depth--;
      j++;
    }
    const window = blanked.slice(j, j + 400);
    const braceRel = window.search(/\{/);
    const semiRel = window.search(/;/);
    if (braceRel === -1) continue;
    if (semiRel !== -1 && semiRel < braceRel) continue; // объявление без тела (.d.ts, overload)
    return j + braceRel;
  }
  return -1;
}

/**
 * Извлекает текст аннотации возврата между закрывающей `)` параметров и `{`
 * тела: снимает завершающую `=>` (стрелочная функция) и ведущее `:`.
 * @param {string} source
 * @param {number} braceStart
 * @returns {string|null} `null`, если аннотации нет
 */
function extractReturnTypeText(source, braceStart) {
  const closeParen = source.lastIndexOf(')', braceStart);
  if (closeParen === -1) return null;
  let header = source.slice(closeParen + 1, braceStart).trim();
  header = header.replace(/=>\s*$/, '').trim();
  if (!header.startsWith(':')) return null;
  header = header.slice(1).trim();
  return header || null;
}

const THROW_KW_RE = /\bthrow\s+/g;
const NEW_CALL_RE = /^new\s+([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(/;
const BARE_IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$.]*$/;
const REJECT_RE = /\bPromise\.reject\s*\(/g;
const EVAL_RE = /\beval\s*\(/;

/**
 * Находит конец `throw`-выражения начиная с позиции сразу после `throw\s+`,
 * не полагаясь на завершающую `;` — ASI (автоматическая вставка точки с
 * запятой) делает `;` необязательной, и это легальный TypeScript. Выражение
 * заканчивается на первой встреченной на "своей" глубине скобок `;`, `\n`
 * или `}` закрывающей ОБЪЕМЛЮЩИЙ блок (глубина открытых внутри выражения
 * `(`/`[`/`{` уже равна нулю к этому месту) — той самой `}`, что раньше
 * ошибочно засчитывалась как часть чужого выражения через регэксп до `;`.
 * @param {string} body
 * @param {number} start
 * @returns {number} индекс конца выражения (символ-граница не входит в него)
 */
function findThrowExpressionEnd(body, start) {
  let depth = 0;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;
  let stringChar = null;
  let inTemplate = false;
  let j = start;
  while (j < body.length) {
    const c = body[j];
    const c2 = body[j + 1];
    if (inLineComment) { if (c === '\n') inLineComment = false; j++; continue; }
    if (inBlockComment) { if (c === '*' && c2 === '/') { inBlockComment = false; j += 2; continue; } j++; continue; }
    if (inString) { if (c === '\\') { j += 2; continue; } if (c === stringChar) inString = false; j++; continue; }
    if (inTemplate) { if (c === '\\') { j += 2; continue; } if (c === '`') inTemplate = false; j++; continue; }
    if (c === '/' && c2 === '/') { inLineComment = true; j += 2; continue; }
    if (c === '/' && c2 === '*') { inBlockComment = true; j += 2; continue; }
    if (c === '"' || c === "'") { inString = true; stringChar = c; j++; continue; }
    if (c === '`') { inTemplate = true; j++; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; j++; continue; }
    if (c === ')' || c === ']') { depth = Math.max(0, depth - 1); j++; continue; }
    if (c === '}') {
      if (depth === 0) return j; // объемлющий блок — граница выражения, не потреблять
      depth--; j++; continue;
    }
    if (depth === 0 && (c === ';' || c === '\n')) return j;
    j++;
  }
  return j;
}

/**
 * Ищет в теле функции сайты, где исход уходит мимо возвращаемого типа:
 * `throw new Foo(...)` и `throw foo;` — распознаваемые формы (escaping);
 * `throw <произвольное выражение>;` (например, `throw map[key];`, вызов
 * фабрики) — форма не разобрана, попадает в `unresolved`, а не теряется.
 * @param {string} body
 * @returns {{ escaping: string[], unresolved: string[] }}
 */
function findEscapingSites(body) {
  const escaping = [];
  const unresolved = [];
  let m;
  THROW_KW_RE.lastIndex = 0;
  while ((m = THROW_KW_RE.exec(body))) {
    const exprStart = THROW_KW_RE.lastIndex;
    const exprEnd = findThrowExpressionEnd(body, exprStart);
    const expr = body.slice(exprStart, exprEnd).trim();
    THROW_KW_RE.lastIndex = exprEnd;
    if (expr === '') continue;
    const newCall = NEW_CALL_RE.exec(expr);
    if (newCall) { escaping.push(`throw new ${newCall[1]}`); continue; }
    if (BARE_IDENT_RE.test(expr)) { escaping.push(`throw ${expr}`); continue; }
    unresolved.push(`throw с неразобранным выражением: ${expr.slice(0, 60)}`);
  }
  REJECT_RE.lastIndex = 0;
  while ((m = REJECT_RE.exec(body))) escaping.push('Promise.reject(');
  if (EVAL_RE.test(body)) unresolved.push('eval(...) — динамический код, не разобрано');
  return { escaping, unresolved };
}

/**
 * @param {string} source
 * @param {string} symbol
 * @returns {import('./shared.mjs').OutcomeExtraction|null}
 */
export function extractOutcomes(source, symbol) {
  const enumMembers = extractEnumMembers(source, symbol);
  if (enumMembers) {
    return { declared: enumMembers, escaping: [], confidence: 'exact', unresolved: [] };
  }

  const rhs = extractTypeAliasRhs(source, symbol);
  if (rhs !== null) {
    const { values, unresolved } = resolveUnionText(source, rhs, new Set([symbol]));
    return { declared: values, escaping: [], confidence: 'syntactic', unresolved };
  }

  const braceStart = findFunctionBraceStart(source, symbol);
  if (braceStart === -1) return null;
  const bodyRes = extractBalancedBraces(source, braceStart, { templateLiterals: true });
  if (!bodyRes) return null;
  const { escaping, unresolved: escapingUnresolved } = findEscapingSites(bodyRes.body);

  const retText = extractReturnTypeText(source, braceStart);
  if (retText === null) {
    return {
      declared: [],
      escaping,
      confidence: 'shallow',
      unresolved: [...escapingUnresolved, 'тип возврата не аннотирован'],
    };
  }

  const promiseMatch = /^Promise<([\s\S]*)>$/.exec(retText);
  const innerText = promiseMatch ? promiseMatch[1] : retText;
  const { values, unresolved } = resolveUnionText(source, innerText, new Set());
  return { declared: values, escaping, confidence: 'syntactic', unresolved: [...escapingUnresolved, ...unresolved] };
}

const PUBLIC_TYPE_RE = /^\s*export\s+(?:declare\s+)?(interface|class|enum|type)\s+([A-Za-z_$][\w$]*)/;

/**
 * Извлекает экспортируемые типы файла (`export interface/class/enum/type`)
 * для `spec.mjs candidates`. В отличие от {@link extractOutcomes}, здесь
 * перечисляются ВСЕ объявления, а не разрешается один символ по имени.
 * @param {string} source
 * @returns {{ name: string, kind: string, line: number, isPublic: boolean, hasSerialization: boolean }[]}
 */
export function extractPublicTypes(source) {
  const lines = source.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = PUBLIC_TYPE_RE.exec(lines[i]);
    if (!m) continue;
    out.push({ name: m[2], kind: m[1], line: i + 1, isPublic: true, hasSerialization: false });
  }
  return out;
}

const PUBLIC_FN_RE = /export\s+(?:async\s+)?function\s*\*?\s+[A-Za-z_$][\w$]*\s*(?:<[^(]*>)?\s*\(/g;

/**
 * Склеивает текст сигнатур всех `export function` (параметры + `: RetType`,
 * без тела) — сигнал «публичная сигнатура» для `spec.mjs candidates`.
 * @param {string} source
 * @returns {string}
 */
export function findPublicSignatureText(source) {
  const spans = [];
  let m;
  PUBLIC_FN_RE.lastIndex = 0;
  while ((m = PUBLIC_FN_RE.exec(source))) {
    const parenStart = source.indexOf('(', m.index);
    let depth = 1;
    let j = parenStart + 1;
    while (j < source.length && depth > 0) {
      if (source[j] === '(') depth++;
      else if (source[j] === ')') depth--;
      j++;
    }
    const tail = source.slice(j, j + 300);
    const endRel = tail.search(/[{;]/);
    spans.push(source.slice(m.index, j) + (endRel === -1 ? tail : tail.slice(0, endRel)));
  }
  return spans.join('\n');
}

export default {
  language: 'typescript',
  extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  extractOutcomes,
  extractPublicTypes,
  findPublicSignatureText,
};
