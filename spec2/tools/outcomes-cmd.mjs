// `spec.mjs outcomes <requirement-id>` — сверка объявленных Outcomes требования
// с исходами кода по его `code:`-якорям (конституция §10). Никакого `--fix`:
// расхождение разрешается человеком одним из трёх путей, названных в выводе.

import fs from 'node:fs';
import path from 'node:path';
import { adapterForFile, supportedExtensions } from './adapters/index.mjs';
import { buildRustWorkspaceResolver } from './rust-workspace.mjs';

/**
 * Находит требование по ID во всём репозитории (не только в одном файле).
 * @param {import('./graph.mjs').Repo} repo
 * @param {string} reqId
 * @returns {{ file: import('./parse.mjs').SpecFile, req: import('./parse.mjs').Requirement }|null}
 */
function findRequirement(repo, reqId) {
  for (const file of repo.files) {
    const req = file.requirements.find((r) => r.id === reqId);
    if (req) return { file, req };
  }
  return null;
}

/**
 * Форматирует один блок расхождения — строго в форме, заданной заданием:
 * без предложения починить, с тремя разрешениями и указанием, что выбор
 * делает человек.
 * @param {string} reqId
 * @param {string} symbol
 * @param {string} variant
 * @returns {string}
 */
function formatDiscrepancy(reqId, symbol, variant) {
  return [
    `РАСХОЖДЕНИЕ  ${reqId}  ${symbol}`,
    `  исход в коде, отсутствует в спеке: ${variant}`,
    '  разрешается ОДНИМ ИЗ:',
    '    (a) исход доменный → добавить в Outcomes и завести сценарий с evidence',
    '    (b) исход не должен возникать → изменить код',
    '    (c) исход не доменный → внести категорию в non_domain_outcomes профиля',
    '  выбор фиксируется человеком; авто-исправления нет',
  ].join('\n');
}

/**
 * Третий исход команды — не "есть расхождение" / "расхождений нет", а
 * "проверка не состоялась": требования нет, якоря нет, файл/адаптер/символ
 * не найдены, либо ни одного варианта фактически не сравнено с Outcomes.
 * Раньше все эти пути возвращали `hasDiscrepancy: false` неотличимо от
 * настоящей полной сверки — команда-страж собственного правила fail-closed
 * (паттерн FC-002) нарушала его сама: отказ по существу был неотличим от
 * невозможности проверить (см. REVIEW.md C3).
 * @typedef {'ok'|'discrepancy'|'unchecked'} OutcomesStatus
 */

/**
 * `spec.mjs outcomes <requirement-id>`.
 * @param {import('./graph.mjs').Repo} repo
 * @param {string} reqId
 * @returns {{ text: string, hasDiscrepancy: boolean, status: OutcomesStatus }}
 */
export function cmdOutcomes(repo, reqId) {
  const found = findRequirement(repo, reqId);
  if (!found) {
    return { text: `требование "${reqId}" не найдено — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`, hasDiscrepancy: false, status: 'unchecked' };
  }
  const { file, req } = found;
  // REVIEW.md M17: профиль требует `code:` именно во frontmatter термина
  // (`kinds.операция.anchors.required: [code, test]`) — команда читала
  // только `req.evidenceAnchors` (Evidence-строки ПОД заголовком требования)
  // и для операции, оформленной строго по профилю, говорила "нет code:-якоря
  // с символом", хотя якорь был, просто во frontmatter файла термина.
  const codeAnchors = [...req.evidenceAnchors, ...file.frontmatterAnchors].filter((a) => a.type === 'code' && a.symbol);
  if (codeAnchors.length === 0) {
    return { text: `у требования ${reqId} нет code:-якоря с символом (ни в Evidence требования, ни в frontmatter anchors: термина) — сверять нечего — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`, hasDiscrepancy: false, status: 'unchecked' };
  }

  const nonDomain = new Set(repo.profile.non_domain_outcomes || []);
  const declaredOutcomes = req.outcomes ? req.outcomes.values : [];
  const outcomeMap = (file.frontmatter && file.frontmatter.outcome_map && file.frontmatter.outcome_map[reqId]) || null;

  const blocks = [];
  const resolveRustType = buildRustWorkspaceResolver(repo.productRoot);
  let hasDiscrepancy = false;
  // true, если хотя бы для одного якоря сверка фактически произошла: не
  // "нет адаптера/файла/символа", не "нет карты — сопоставьте вручную",
  // и вариантов для сравнения было больше нуля.
  let anyVerified = false;
  // true, если хотя бы один якорь не удалось довести до сверки — эта
  // причина обязана попасть в итоговый статус, а не потеряться за
  // "расхождений нет" по другим якорям.
  let anyUnchecked = false;

  for (const anchor of codeAnchors) {
    const absPath = path.join(repo.productRoot, anchor.file);
    if (!fs.existsSync(absPath)) {
      blocks.push(`якорь ${anchor.type}:${anchor.target} — файл не найден: ${anchor.file} — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`);
      anyUnchecked = true;
      continue;
    }
    const adapter = adapterForFile(anchor.file);
    if (!adapter) {
      blocks.push(
        `якорь ${anchor.type}:${anchor.target} — нет адаптера для языка файла ${anchor.file} ` +
        `(поддерживаются: ${supportedExtensions().join(', ')}) — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`,
      );
      anyUnchecked = true;
      continue;
    }
    const source = fs.readFileSync(absPath, 'utf8');
    const extraction = adapter.extractOutcomes(
      source,
      anchor.symbol,
      adapter.language === 'rust'
        ? { resolveType: (name) => resolveRustType(name, { sourceFile: anchor.file, source }) }
        : {},
    );
    if (extraction === null) {
      blocks.push(`символ "${anchor.symbol}" в ${anchor.file} не найден либо не разобран — сверять нечего — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`);
      anyUnchecked = true;
      continue;
    }
    const { declared: variants, escaping, confidence, unresolved } = extraction;

    // Побег мимо типа и неразобранные конструкции — не участвуют в сверке
    // с Outcomes (у них нет имени варианта для outcome_map), но обязаны
    // попасть в вывод: конституция §10 требует не терять их молча.
    if (escaping.length > 0 || unresolved.length > 0) {
      const infoLines = [`СВЕДЕНИЯ ОБ ИСХОДАХ  ${reqId}  ${anchor.symbol}  (confidence: ${confidence})`];
      if (escaping.length > 0) {
        infoLines.push(`  исходы мимо типа (escaping): ${escaping.join(', ')}`);
        infoLines.push('  для них ветка (b) почти всегда верна: убрать бросок из кода');
      }
      if (unresolved.length > 0) {
        infoLines.push(`  не разобрано: ${unresolved.join(', ')}`);
        infoLines.push('  достоверность вывода ниже — проверьте эти места вручную');
      }
      blocks.push(infoLines.join('\n'));
      // A mapped subset is not a complete check when the adapter explicitly
      // says that another exit path or type detail was not resolved. Keep the
      // useful comparison below, but never report the command as verified.
      anyUnchecked = true;
    }

    if (!outcomeMap) {
      blocks.push(
        [
          `СОПОСТАВЛЕНИЕ ВРУЧНУЮ  ${reqId}  ${anchor.symbol}`,
          `  confidence: ${confidence}`,
          `  исходы кода:   ${variants.join(', ') || '(нет вариантов)'}`,
          `  исходы спеки:  ${declaredOutcomes.join(', ') || '(Outcomes не объявлены)'}`,
          '  явной карты (frontmatter.outcome_map) для этого требования нет — сопоставьте вручную',
        ].join('\n'),
      );
      anyUnchecked = true; // без карты автоматической сверки не было — это тоже не "проверено"
      continue;
    }

    // Адаптер нашёл символ, но не смог перечислить ни одного варианта
    // (напр. confidence:"shallow" — тип возврата не аннотирован): цикл
    // ниже не выполнится ни разу, и без этой пометки якорь молча
    // засчитался бы как "всё сопоставлено" при нуле сравнений
    // (воспроизведено Codex на реальном outcomes REV-002, см. REVIEW.md C3).
    if (variants.length === 0) {
      blocks.push(
        `якорь ${anchor.type}:${anchor.target} (символ "${anchor.symbol}") — адаптер не извлёк ни одного ` +
        `варианта исхода (confidence: ${confidence}) — ПРОВЕРКА НЕ СОСТОЯЛАСЬ`,
      );
      anyUnchecked = true;
      continue;
    }

    for (const variant of variants) {
      anyVerified = true;
      const mapped = outcomeMap[variant];
      if (mapped === undefined) {
        blocks.push(formatDiscrepancy(reqId, anchor.symbol, variant));
        hasDiscrepancy = true;
        continue;
      }
      if (nonDomain.has(mapped)) continue; // исключено профилем — не доменный исход
      if (!declaredOutcomes.includes(mapped)) {
        blocks.push(formatDiscrepancy(reqId, anchor.symbol, `${variant} → "${mapped}"`));
        hasDiscrepancy = true;
      }
    }
  }

  /** @type {OutcomesStatus} */
  let status;
  if (hasDiscrepancy) status = 'discrepancy';
  else if (anyUnchecked || !anyVerified) status = 'unchecked';
  else status = 'ok';

  const text = blocks.length > 0
    ? blocks.join('\n\n')
    : `расхождений нет: все варианты code:-якорей ${reqId} сопоставлены с Outcomes`;
  return { text, hasDiscrepancy, status };
}
