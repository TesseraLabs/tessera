#!/usr/bin/env node
// Точка входа CLI spec2: lint / graph / context / why.
// Корень репозитория — две директории вверх от этого файла (spec2/tools/../..
// даёт корень продукта, где `crates/...` и т.п. — сам spec2/ на уровень выше tools/).

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadRepo, buildGraph } from './graph.mjs';
import { lint, formatFinding } from './lint.mjs';
import { contextSlice, reviewSlice, why } from './slice.mjs';
import { cmdOutcomes } from './outcomes-cmd.mjs';
import { cmdCandidates } from './candidates-cmd.mjs';
import { formatFlow } from './flow.mjs';
import { draftPage } from './draft.mjs';
import { buildTrace, formatTrace } from './trace.mjs';
import { decisionReport, formatDecisionReport } from './decision.mjs';
import { buildDoctorReport, formatDoctorReport } from './doctor.mjs';
import { auditE2E, formatE2EAudit } from './e2e-audit.mjs';
import { buildReviewImpact, formatReviewImpact } from './review-impact.mjs';
import { buildOpenSpecCoverage, formatOpenSpecCoverage } from './openspec-coverage.mjs';
import { buildQualityReport, formatQualityReport } from './quality.mjs';
import { buildNextQueue, formatNextQueue } from './next.mjs';
import { buildChangeReport, formatChangeReport } from './change.mjs';
import { loadRepoAtGitRef, changedFilesBetween } from './git-snapshot.mjs';
import { buildSemanticReview, formatSemanticReview } from './semantic-review.mjs';

// Вывод CLI обязан переживать `| head` / `| grep` / любой потребитель,
// закрывающий трубу раньше, чем весь вывод записан: без обработчика `error`
// на stdout закрытая труба даёт необработанный EPIPE и падение процесса со
// стектрейсом Node — регрессия перехода на естественное завершение через
// `process.exitCode` ниже (оно держит процесс дольше немедленного выхода,
// и запись в уже закрытую трубу успевает произойти).
// Немедленное завершение процесса здесь намеренно не используется — см.
// комментарий у "process.exitCode" в конце файла про обрыв асинхронной
// записи в пайп: достаточно поглотить именно EPIPE, чтобы запись в закрытую
// трубу не бросала синхронно из process.stdout.write(...) и не роняла процесс
// необработанным исключением; естественное завершение после того, как весь
// синхронный код отработает, делает то же самое без обрыва.
process.stdout.on('error', (err) => {
  if (err && err.code === 'EPIPE') return;
  throw err;
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SPEC2_ROOT = path.resolve(__dirname, '..');
// Корень репозитория продукта (где живут evidence-якоря `code:`/`test:`/`schema:`) —
// на уровень выше spec2/, т.е. две директории вверх от tools/.
const PRODUCT_ROOT = path.resolve(__dirname, '..', '..');

/**
 * Сигнал «показать usage и завершиться с кодом 2» — не `Error` по смыслу,
 * а управление потоком: `usage()` не возвращается к вызвавшей ветке. Ловится
 * один раз, на самом верху, чтобы код завершения был выставлен ПОСЛЕ того,
 * как event loop опустеет и весь `stdout`/`stderr` реально уйдёт в пайп —
 * см. комментарий у `process.exit` ниже.
 */
class UsageSignal extends Error {}

/**
 * Печатает использование CLI. Не завершает процесс сама — бросает
 * {@link UsageSignal}, которую ловит точка входа внизу файла.
 */
function usage() {
  process.stderr.write(
    [
      'Использование:',
      '  spec.mjs lint',
      '  spec.mjs graph',
      '  spec.mjs flow <id>                       (причинный срез по relation_types.*.flow)',
      '  spec.mjs draft <kind> <context.id> --name <название>  (заготовка в stdout)',
      '  spec.mjs trace [<requirement-id|context.id>] [--missing] [--json]',
      '  spec.mjs decision <context.ADR-id> [--json]',
      '  spec.mjs context <id> --slice <implement|why|review>',
      '  spec.mjs context --slice review --seed-files <файл со списком путей>',
      '  spec.mjs context --slice review --seed-git <git-ref>   (берёт "git diff --name-only <ref>")',
      '  spec.mjs why <path>[#symbol]',
      '  spec.mjs outcomes <requirement-id>   (сверка с кодом; --fix не существует — конституция §10)',
      '  spec.mjs candidates [--new]          (кандидаты в термины; вердикт — spec2/candidates.yaml)',
      '  spec.mjs doctor [--json] [--strict]  (единый health-report)',
      '  spec.mjs quality [--all] [--json] [--strict]  (сигналы ложной зелени)',
      '  spec.mjs next [--all] [--json] [--strict]     (приоритизированная очередь)',
      '  spec.mjs e2e [--missing] [--json]    (точность связей E2E ↔ spec2)',
      '  spec.mjs review (--seed-files <file>|--seed-git <ref>) [--json]',
      '  spec.mjs review --base <ref> [--head <ref>] [--json] [--strict]  (semantic diff)',
      '  spec.mjs change (--seed-files <file>|--seed-git <ref>|--base <ref> [--head <ref>]) [--json]',
      '  spec.mjs coverage [--missing] [--json]  (OpenSpec requirement → spec2 norm)',
      '',
    ].join('\n'),
  );
  throw new UsageSignal();
}

function changedFilesFromArgs(args) {
  const seedFilesIdx = args.indexOf('--seed-files');
  const seedGitIdx = args.indexOf('--seed-git');
  if ((seedFilesIdx === -1) === (seedGitIdx === -1)) usage();
  if (seedFilesIdx !== -1) {
    const listPath = args[seedFilesIdx + 1];
    if (!listPath) usage();
    return fs.readFileSync(listPath, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  }
  const ref = args[seedGitIdx + 1];
  if (!ref) usage();
  return execFileSync('git', ['diff', '--name-only', ref], { cwd: PRODUCT_ROOT, encoding: 'utf8' })
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

function withSemanticInputs(args, callback) {
  if (args.includes('--seed-files') || args.includes('--seed-git')) usage();
  const baseIdx = args.indexOf('--base');
  if (baseIdx === -1 || !args[baseIdx + 1]) usage();
  const baseRef = args[baseIdx + 1];
  const headIdx = args.indexOf('--head');
  const headRef = headIdx === -1 ? null : args[headIdx + 1];
  if (headIdx !== -1 && !headRef) usage();

  const baseSnapshot = loadRepoAtGitRef(PRODUCT_ROOT, baseRef);
  let headSnapshot = null;
  try {
    headSnapshot = headRef ? loadRepoAtGitRef(PRODUCT_ROOT, headRef) : null;
    const headRepo = headSnapshot?.repo || loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const changedFiles = changedFilesBetween(PRODUCT_ROOT, baseRef, headRef);
    return callback({
      baseRepo: baseSnapshot.repo,
      headRepo,
      changedFiles,
      labels: { base: `${baseRef}@${baseSnapshot.commit.slice(0, 12)}`, head: headSnapshot ? `${headRef}@${headSnapshot.commit.slice(0, 12)}` : 'worktree' },
    });
  } finally {
    if (headSnapshot) headSnapshot.cleanup();
    baseSnapshot.cleanup();
  }
}

/**
 * @param {string[]} argv
 */
function main(argv) {
  const [cmd, ...rest] = argv;

  if (cmd === 'lint') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const findings = lint(repo);
    for (const f of findings) process.stdout.write(formatFinding(f) + '\n');
    const hasError = findings.some((f) => f.level === 'ERROR');
    process.exitCode = hasError ? 1 : 0;
    return;
  }

  if (cmd === 'graph') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const graph = buildGraph(repo);
    const outPath = path.join(SPEC2_ROOT, 'graph.json');
    fs.writeFileSync(outPath, JSON.stringify(graph, null, 2) + '\n', 'utf8');
    process.stdout.write(`граф записан: ${path.relative(process.cwd(), outPath)} (узлов: ${graph.nodes.length}, рёбер: ${graph.edges.length})\n`);
    return;
  }

  if (cmd === 'flow') {
    const [id] = rest;
    if (!id) usage();
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    try {
      process.stdout.write(formatFlow(repo, id) + '\n');
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }

  if (cmd === 'draft') {
    const [kind, qualifiedId] = rest;
    if (!kind || !qualifiedId) usage();
    const nameIdx = rest.indexOf('--name');
    const name = nameIdx !== -1 ? rest[nameIdx + 1] : undefined;
    if (nameIdx !== -1 && !name) usage();
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    try {
      process.stdout.write(draftPage(repo, kind, qualifiedId, name));
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }

  if (cmd === 'trace') {
    const target = rest.find((arg) => !arg.startsWith('--')) || null;
    const missingOnly = rest.includes('--missing');
    const json = rest.includes('--json');
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    try {
      const rows = buildTrace(repo, { target, missingOnly });
      process.stdout.write(json ? `${JSON.stringify(rows, null, 2)}\n` : `${formatTrace(rows, { missingOnly })}\n`);
      process.exitCode = missingOnly && rows.length > 0 ? 1 : 0;
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 2;
    }
    return;
  }

  if (cmd === 'decision') {
    const id = rest.find((arg) => !arg.startsWith('--'));
    if (!id) usage();
    const json = rest.includes('--json');
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    try {
      const report = decisionReport(repo, id);
      process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : `${formatDecisionReport(report)}\n`);
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 2;
    }
    return;
  }

  if (cmd === 'context') {
    const sliceIdx = rest.indexOf('--slice');
    const sliceName = sliceIdx !== -1 ? rest[sliceIdx + 1] : null;
    if (!sliceName) usage();
    const seedFilesIdx = rest.indexOf('--seed-files');
    const seedGitIdx = rest.indexOf('--seed-git');

    if (seedFilesIdx !== -1 || seedGitIdx !== -1) {
      // Засев среза "review" списком изменённых файлов (profile.yaml:
      // slices.review.seed: [изменённые-файлы]) — id-позиционника здесь нет,
      // seed приходит извне: либо файлом со списком путей, либо `git diff`
      // относительно указанного ref.
      let seedFiles;
      if (seedFilesIdx !== -1) {
        const listPath = rest[seedFilesIdx + 1];
        if (!listPath) usage();
        seedFiles = fs.readFileSync(listPath, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      } else {
        const ref = rest[seedGitIdx + 1];
        if (!ref) usage();
        seedFiles = execFileSync('git', ['diff', '--name-only', ref], { cwd: PRODUCT_ROOT, encoding: 'utf8' })
          .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      }
      const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
      try {
        process.stdout.write(reviewSlice(repo, seedFiles) + '\n');
      } catch (e) {
        process.stderr.write(`${e.message}\n`);
        process.exitCode = 1;
      }
      return;
    }

    const id = rest[0];
    if (!id) usage();
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    try {
      process.stdout.write(contextSlice(repo, id, sliceName) + '\n');
    } catch (e) {
      process.stderr.write(`${e.message}\n`);
      process.exitCode = 1;
    }
    return;
  }

  if (cmd === 'why') {
    const [target] = rest;
    if (!target) usage();
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    process.stdout.write(why(repo, target) + '\n');
    return;
  }

  if (cmd === 'outcomes') {
    const [reqId] = rest;
    if (!reqId) usage();
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const { text, status } = cmdOutcomes(repo, reqId);
    process.stdout.write(text + '\n');
    // Три исхода, три кода возврата: 0 — сверка состоялась и расхождений нет,
    // 1 — сверка состоялась и нашла расхождение, 2 — сверка НЕ состоялась
    // (нет требования/якоря/адаптера/символа, либо ни одного варианта не
    // сравнено). 0 зарезервирован строго за первым случаем — CI не вправе
    // читать "не удалось проверить" как "проверено, всё чисто" (C3).
    process.exitCode = status === 'discrepancy' ? 1 : status === 'unchecked' ? 2 : 0;
    return;
  }

  if (cmd === 'candidates') {
    const onlyNew = rest.includes('--new');
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const { text, hasNew } = cmdCandidates(repo, { onlyNew });
    process.stdout.write(text + '\n');
    process.exitCode = onlyNew && hasNew ? 1 : 0;
    return;
  }

  if (cmd === 'doctor') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildDoctorReport(repo);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatDoctorReport(report)}\n`);
    process.exitCode = report.status === 'error' || (report.status === 'warn' && rest.includes('--strict')) ? 1 : 0;
    return;
  }

  if (cmd === 'quality') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildQualityReport(repo);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatQualityReport(report, { all: rest.includes('--all') })}\n`);
    process.exitCode = rest.includes('--strict') && report.total ? 1 : 0;
    return;
  }

  if (cmd === 'next') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildNextQueue(repo);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatNextQueue(report, { all: rest.includes('--all') })}\n`);
    process.exitCode = rest.includes('--strict') && (report.counts.P0 || report.counts.P1) ? 1 : 0;
    return;
  }

  if (cmd === 'e2e') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = auditE2E(repo);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatE2EAudit(report, { missingOnly: rest.includes('--missing') })}\n`);
    process.exitCode = report.counts.missing || report.counts.invalid ? 1 : 0;
    return;
  }

  if (cmd === 'review') {
    if (rest.includes('--base')) {
      const report = withSemanticInputs(rest, ({ baseRepo, headRepo, changedFiles, labels }) => buildSemanticReview(baseRepo, headRepo, changedFiles, labels));
      process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatSemanticReview(report)}\n`);
      process.exitCode = report.semantic.risk === 'high' || (rest.includes('--strict') && report.semantic.risk === 'medium') ? 1 : 0;
      return;
    }
    const changedFiles = changedFilesFromArgs(rest);
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildReviewImpact(repo, changedFiles);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatReviewImpact(report)}\n`);
    return;
  }

  if (cmd === 'change') {
    if (rest.includes('--base')) {
      const report = withSemanticInputs(rest, ({ baseRepo, headRepo, changedFiles, labels }) => {
        const semantic = buildSemanticReview(baseRepo, headRepo, changedFiles, labels).semantic;
        return buildChangeReport(headRepo, changedFiles, { semanticDiff: semantic });
      });
      process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatChangeReport(report)}\n`);
      process.exitCode = report.risk === 'high' ? 1 : 0;
      return;
    }
    const changedFiles = changedFilesFromArgs(rest);
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildChangeReport(repo, changedFiles);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatChangeReport(report)}\n`);
    process.exitCode = report.risk === 'high' ? 1 : 0;
    return;
  }

  if (cmd === 'coverage') {
    const repo = loadRepo(SPEC2_ROOT, PRODUCT_ROOT);
    const report = buildOpenSpecCoverage(repo);
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : `${formatOpenSpecCoverage(report, { missingOnly: rest.includes('--missing') })}\n`);
    process.exitCode = report.counts.missing || report.counts.duplicate || report.counts.unknown ? 1 : 0;
    return;
  }

  usage();
}

// Форсированное завершение процесса сразу после stdout.write обрывает вывод
// при пайпе: запись в пайп асинхронна, а немедленное завершение случается
// раньше, чем буфер уйдёт получателю (наблюдалось на `candidates` — длинные
// строки обрезались на середине пути в ~1 запуске из 3). Правильный способ —
// `process.exitCode` и естественное завершение, когда event loop опустеет и
// весь вывод гарантированно сброшен.
try {
  main(process.argv.slice(2));
} catch (e) {
  if (e instanceof UsageSignal) {
    process.exitCode = 2;
  } else {
    throw e;
  }
}
