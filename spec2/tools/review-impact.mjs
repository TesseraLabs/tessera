import { buildTrace } from './trace.mjs';

function normalize(raw) {
  return String(raw).trim().replace(/\\/g, '/').replace(/^\.\//, '');
}

function anchorFile(target) {
  return String(target).split('#')[0];
}

/** Структурированный impact: сначала contexts, затем terms и requirements. */
export function buildReviewImpact(repo, changedFiles) {
  const changed = [...new Set(changedFiles.map(normalize).filter(Boolean))].sort();
  const changedSet = new Set(changed);
  const trace = buildTrace(repo);
  const contexts = new Map();
  const matchedFiles = new Set();

  function contextFor(context) {
    if (!contexts.has(context)) contexts.set(context, { id: context, terms: new Map(), requirements: [], decisions: new Set() });
    return contexts.get(context);
  }

  function addTerm(ctx, entity, reasons) {
    const existing = ctx.terms.get(entity.id);
    if (existing) {
      existing.reasons = [...new Set([...existing.reasons, ...reasons])];
      return;
    }
    ctx.terms.set(entity.id, { id: entity.id, kind: entity.kind, path: entity.path, reasons: [...new Set(reasons)] });
  }

  // Сначала сопоставляем сами страницы и якоря сущностей. Иначе термин или
  // ADR без requirements исчезает из review только потому, что для него нет
  // строки в trace-матрице.
  for (const entity of repo.entities) {
    const reasons = [];
    const ownerSpecPath = `spec2/${entity.path}`;
    if (changedSet.has(entity.path) || changedSet.has(ownerSpecPath)) {
      reasons.push(`спека:${entity.path}`);
      matchedFiles.add(changedSet.has(ownerSpecPath) ? ownerSpecPath : entity.path);
    }
    for (const anchor of entity.file.frontmatterAnchors) {
      const file = anchorFile(anchor.target);
      if (!changedSet.has(file)) continue;
      reasons.push(`якорь:${anchor.type}:${anchor.target}`);
      matchedFiles.add(file);
    }
    if (!reasons.length) continue;
    const qualifiedEntity = { ...entity, id: `${entity.context}.${entity.id}` };
    const ctx = contextFor(entity.context);
    addTerm(ctx, qualifiedEntity, reasons);
    if (entity.kind === repo.decisionKind) ctx.decisions.add(qualifiedEntity.id);
  }

  for (const row of trace) {
    const ownerSpecPath = `spec2/${row.owner.path}`;
    const reasons = [];
    if (changedSet.has(row.owner.path) || changedSet.has(ownerSpecPath)) {
      reasons.push(`спека:${row.owner.path}`);
      matchedFiles.add(changedSet.has(ownerSpecPath) ? ownerSpecPath : row.owner.path);
    }
    for (const anchor of row.evidence) {
      const file = anchorFile(anchor.target);
      if (changedSet.has(file)) {
        reasons.push(`evidence:${anchor.type}:${anchor.target}`);
        matchedFiles.add(file);
      }
    }
    for (const subject of row.subjects) {
      for (const anchor of subject.anchors) {
        const file = anchorFile(anchor.target);
        if (changedSet.has(file)) {
          reasons.push(`субъект:${subject.id}:${anchor.type}:${anchor.target}`);
          matchedFiles.add(file);
        }
      }
    }
    if (reasons.length === 0) continue;

    const context = row.owner.context || row.owner.id.split('.')[0];
    const ctx = contextFor(context);
    addTerm(ctx, row.owner, reasons);
    ctx.requirements.push({ id: row.id, title: row.title, kind: row.kind, owner: row.owner.id, reasons: [...new Set(reasons)], gaps: row.gaps, outcomes: row.outcomes });
    for (const decision of row.decisions) ctx.decisions.add(decision);
  }

  const resultContexts = [...contexts.values()].sort((a, b) => a.id.localeCompare(b.id)).map((ctx) => ({
    id: ctx.id,
    title: repo.profile.contexts?.[ctx.id]?.title || ctx.id,
    terms: [...ctx.terms.values()].sort((a, b) => a.id.localeCompare(b.id)),
    requirements: ctx.requirements.sort((a, b) => a.id.localeCompare(b.id)),
    decisions: [...ctx.decisions].sort(),
  }));
  return { changedFiles: changed, matchedFiles: [...matchedFiles].sort(), unmappedFiles: changed.filter((file) => !matchedFiles.has(file)), contexts: resultContexts };
}

export function formatReviewImpact(report) {
  const affected = report.contexts.reduce((sum, ctx) => sum + ctx.requirements.length, 0);
  const lines = [
    `Review impact: ${report.changedFiles.length} файлов → ${report.contexts.length} контекстов → ${affected} норм`,
  ];
  if (report.unmappedFiles.length) {
    lines.push('', `Не сопоставлены (${report.unmappedFiles.length}):`, ...report.unmappedFiles.map((file) => `- ${file}`));
  }
  for (const ctx of report.contexts) {
    lines.push('', `## ${ctx.id} — ${ctx.title}`);
    lines.push(`Термины: ${ctx.terms.map((term) => term.id).join(', ') || '—'}`);
    for (const term of ctx.terms) {
      if (!term.reasons?.length) continue;
      lines.push(`- ${term.id} [${term.kind}]`);
      for (const reason of term.reasons) lines.push(`  - задет через ${reason}`);
    }
    if (ctx.decisions.length) lines.push(`Решения: ${ctx.decisions.join(', ')}`);
    for (const req of ctx.requirements) {
      lines.push(`- ${req.id} — ${req.title} [${req.kind}]`);
      for (const reason of req.reasons) lines.push(`  - задет через ${reason}`);
      if (req.gaps.length) lines.push(`  - gaps: ${req.gaps.join(', ')}`);
      lines.push(`  - детали: spec.mjs context ${req.id} --slice review`);
    }
  }
  return lines.join('\n');
}
