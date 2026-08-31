// Разбор и проверка раздела "## Combinations" (конституция §10): решающая
// таблица по нескольким измерениям, где `*` означает «любое значение», а
// значение ячейки может быть дизъюнкцией через экранированный `\|`.

/**
 * @typedef {{ name: string, values: string[], line: number }} Dimension
 * @typedef {{ line: number, num: string, dimValues: string[], outcomeRaw: string,
 *   outcome: string|null, undefined: boolean, columnMismatch: boolean }} CombinationRow
 * @typedef {{ dims: Dimension[], rows: CombinationRow[], sectionLine: number,
 *   unparsedDimLines: Array<{line: number, text: string}> }} CombinationsTable
 */

// Тире между именем измерения и списком значений: раньше принимался только
// длинный U+2014 ("—"). Короткое тире ("–") и обычный дефис ("-") — то же
// намерение автора, только другой символ на клавиатуре/автозамене редактора;
// отвергать их означало терять измерение целиком, а с ним — весь раздел
// (REVIEW.md H3).
const DIM_RE = /^-\s*`([^`]+)`\s*[—–-]\s*(.+)$/;

/**
 * Снимает обрамляющие бэктики, если значение целиком в них заключено.
 * @param {string} s
 * @returns {string}
 */
function stripBackticks(s) {
  const t = s.trim();
  if (t.length >= 2 && t[0] === '`' && t[t.length - 1] === '`') return t.slice(1, -1).trim();
  return t;
}

/**
 * Разбирает список значений измерения после тире: элементы разделены `|`,
 * бэктики вокруг отдельного значения необязательны — в файлах спеки
 * встречаются оба варианта.
 * @param {string} rest
 * @returns {string[]}
 */
function splitDimValues(rest) {
  return rest.split('|').map((s) => stripBackticks(s)).filter((s) => s !== '');
}

/**
 * Разбирает одну строку markdown-таблицы на ячейки. `|` внутри значения
 * ячейки экранируется как `\|` — это нужно для дизъюнкции значений измерения
 * в одной ячейке (например, "устарела \| непроверяема").
 * @param {string} line
 * @returns {string[]}
 */
function splitTableRow(line) {
  const body = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  const cells = [];
  let cur = '';
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\' && body[i + 1] === '|') { cur += '|'; i += 1; continue; }
    if (body[i] === '|') { cells.push(cur.trim()); cur = ''; continue; }
    cur += body[i];
  }
  cells.push(cur.trim());
  return cells;
}

/**
 * Извлекает имя исхода из ячейки последнего столбца: первая подстрока в
 * бэктиках, либо специальная пометка "**НЕ ОПРЕДЕЛЕНО**" — легальная
 * задокументированная дыра (конституция §10), а не ошибка.
 * @param {string} cell
 * @returns {{ outcome: string|null, isUndefined: boolean }}
 */
function extractOutcomeCell(cell) {
  if (/\*\*НЕ ОПРЕДЕЛЕНО\*\*/.test(cell)) return { outcome: null, isUndefined: true };
  const m = /`([^`]+)`/.exec(cell);
  return { outcome: m ? m[1].trim() : null, isUndefined: false };
}

/**
 * Разбирает ОДИН раздел "## Combinations", начинающийся с заголовка `headings[idx]`.
 * @param {string[]} bodyLines
 * @param {number} bodyStartLine
 * @param {{level:number,text:string,line:number}[]} headings
 * @param {number} idx индекс заголовка "Combinations" в `headings`
 * @returns {CombinationsTable}
 */
function parseOneCombinationsSection(bodyLines, bodyStartLine, headings, idx) {
  const start = headings[idx].line;
  let end = bodyStartLine + bodyLines.length;
  for (let j = idx + 1; j < headings.length; j++) {
    if (headings[j].level <= headings[idx].level) { end = headings[j].line; break; }
  }

  // Измерения — только маркированный список ДО первой строки таблицы: тем же
  // синтаксисом ("- `имя` — значения") может случайно совпасть проза в
  // подразделах ПОСЛЕ таблицы (например, разбор дыры в строке 17), и её
  // подхватывать нельзя.
  /** @type {Dimension[]} */
  const dims = [];
  /** @type {Array<{line: number, text: string}>} */
  const unparsedDimLines = [];
  let tableStart = -1;
  for (let ln = start; ln < end; ln++) {
    const raw = bodyLines[ln - bodyStartLine];
    if (raw === undefined) continue;
    const trimmed = raw.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('|')) { tableStart = ln; break; }
    const dm = DIM_RE.exec(trimmed);
    if (dm) { dims.push({ name: dm[1].trim(), values: splitDimValues(dm[2]), line: ln }); continue; }
    // Непустая строка в известном разделе "## Combinations" перед таблицей,
    // похожая на попытку объявить измерение (начинается с "- "), но не
    // разобранная DIM_RE — молчаливый пропуск здесь равен потере измерения,
    // а с ним и всей проверки полноты таблицы (REVIEW.md H3). Заголовок
    // раздела сам по себе (строка `start`) сюда не попадает — цикл начинается
    // с `start`, но заголовок это первая строка и она уже потреблена findHeadings
    // отдельно, здесь встречается только ТЕЛО секции после заголовка.
    if (trimmed.startsWith('- ') || trimmed.startsWith('-`')) {
      unparsedDimLines.push({ line: ln, text: trimmed });
    }
  }

  // Строки таблицы — непрерывный блок начиная с tableStart, пока строки
  // остаются табличными (пустая строка или проза после таблицы его завершает).
  /** @type {Array<{ln:number, text:string}>} */
  const tableLines = [];
  if (tableStart !== -1) {
    for (let ln = tableStart; ln < end; ln++) {
      const raw = bodyLines[ln - bodyStartLine];
      if (raw === undefined || !raw.trim().startsWith('|')) break;
      tableLines.push({ ln, text: raw });
    }
  }

  /** @type {CombinationRow[]} */
  const rows = [];
  // tableLines[0] — заголовок таблицы, tableLines[1] — разделитель "|---|...",
  // с tableLines[2] начинаются данные.
  for (let i = 2; i < tableLines.length; i++) {
    const cells = splitTableRow(tableLines[i].text);
    const num = cells[0] ?? '';
    const dimValues = cells.slice(1, 1 + dims.length);
    const outcomeCell = cells[1 + dims.length] ?? '';
    const { outcome, isUndefined } = extractOutcomeCell(outcomeCell);
    // "# | измерения... | Исход" — потерянное измерение (напр. из-за
    // unparsedDimLines выше) сдвигает все последующие ячейки; число ячеек
    // строки данных обязано быть dims.length + 2 (номер + измерения + исход),
    // иначе сверка идёт по смещённым значениям молча (REVIEW.md H3).
    const columnMismatch = cells.length !== dims.length + 2;
    rows.push({ line: tableLines[i].ln, num, dimValues, outcomeRaw: outcomeCell, outcome, undefined: isUndefined, columnMismatch });
  }

  return { dims, rows, sectionLine: start, unparsedDimLines };
}

/**
 * Находит и разбирает ВСЕ разделы "## Combinations" файла — список измерений
 * (маркированный список `- \`имя\` — знач1 | знач2`) и таблицу под каждым.
 * Раньше `headings.findIndex(...)` брал только ПЕРВОЕ совпадение — второй
 * раздел "## Combinations" в файле не проверялся вовсе, и об этом не
 * сообщалось ни строкой (REVIEW.md M6). Возвращает пустой массив, если ни
 * одного раздела в файле нет.
 * @param {string[]} bodyLines
 * @param {number} bodyStartLine
 * @param {{level:number,text:string,line:number}[]} headings
 * @returns {CombinationsTable[]}
 */
export function parseCombinations(bodyLines, bodyStartLine, headings) {
  const tables = [];
  for (let idx = 0; idx < headings.length; idx++) {
    if (headings[idx].text.trim() !== 'Combinations') continue;
    tables.push(parseOneCombinationsSection(bodyLines, bodyStartLine, headings, idx));
  }
  return tables;
}

/**
 * Проверяет, покрывает ли сырое значение ячейки (возможно, дизъюнкция через
 * `|` и/или `*` — «любое значение») конкретное значение измерения.
 * @param {string} cellRaw
 * @param {string} value
 * @returns {boolean}
 */
export function cellCoversValue(cellRaw, value) {
  const parts = cellRaw.split('|').map((s) => s.trim()).filter((s) => s !== '');
  for (const p of parts) if (p === '*' || p === value) return true;
  return false;
}

/**
 * Раскрывает измерения в декартово произведение конкретных сочетаний значений.
 * @param {Dimension[]} dims
 * @returns {string[][]}
 */
export function cartesianProduct(dims) {
  let result = [[]];
  for (const dim of dims) {
    const next = [];
    for (const partial of result) for (const v of dim.values) next.push([...partial, v]);
    result = next;
  }
  return result;
}

/**
 * Проверяет полноту и непересечение таблицы: для каждого раскрытого сочетания
 * значений — сколько строк таблицы его покрывает (конституция §10: полнота —
 * каждое сочетание в хотя бы одной строке, непересечение — не более чем в одной).
 * @param {CombinationsTable} table
 * @returns {{ uncovered: string[][], overlaps: Array<{ combo: string[], rows: CombinationRow[] }> }}
 */
export function analyzeCoverage(table) {
  const combos = cartesianProduct(table.dims);
  const uncovered = [];
  const overlaps = [];
  for (const combo of combos) {
    const covering = table.rows.filter((row) =>
      combo.every((value, i) => cellCoversValue(row.dimValues[i] ?? '', value)),
    );
    if (covering.length === 0) uncovered.push(combo);
    else if (covering.length > 1) overlaps.push({ combo, rows: covering });
  }
  return { uncovered, overlaps };
}

/**
 * Считает, сколько раскрытых сочетаний покрыты ИСКЛЮЧИТЕЛЬНО строкой(ами)
 * "**НЕ ОПРЕДЕЛЕНО**" (REVIEW.md M16): такое сочетание проходит
 * {@link analyzeCoverage} как "покрыто" (таблица формально полна), но
 * поведение для него не определено — это задокументированная дыра, а не
 * ошибка, и требование E-COMBINATIONS-NOT-TOTAL не обязано на неё срабатывать
 * (иначе таблица, полностью честно объявляющая дыру, никогда не прошла бы
 * линт). Но замалчивать сам факт нельзя — сообщение о полноте обязано
 * называть число таких сочетаний, а не выглядеть чистой полнотой по волшебству.
 * @param {CombinationsTable} table
 * @returns {number}
 */
export function countUndefinedOnlyCoverage(table) {
  const combos = cartesianProduct(table.dims);
  let count = 0;
  for (const combo of combos) {
    const covering = table.rows.filter((row) =>
      combo.every((value, i) => cellCoversValue(row.dimValues[i] ?? '', value)),
    );
    if (covering.length > 0 && covering.every((r) => r.undefined)) count++;
  }
  return count;
}

/**
 * Форматирует конкретное сочетание значений измерений для сообщения линта.
 * @param {Dimension[]} dims
 * @param {string[]} combo
 * @returns {string}
 */
export function formatCombo(dims, combo) {
  return combo.map((v, i) => `${dims[i].name}=${v}`).join(', ');
}
