import { buildReviewImpact } from './review-impact.mjs';

const OMITTED_PROPERTIES = new Set(['id', 'context', 'kind', 'name', 'status', 'anchors', 'relations', 'requirements']);

function normalizeText(value) {
  return String(value || '').replace(/\s+/gu, ' ').trim();
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}

function stable(value) {
  return JSON.stringify(canonical(value));
}

function sorted(values) {
  return [...new Set(values.map(String))].sort();
}

function qualify(ref, context) {
  const value = String(ref);
  return value.includes('.') ? value : `${context}.${value}`;
}

function anchorKey(owner, anchor) {
  return `${owner}|${anchor.type}|${anchor.target}`;
}

function proseOutsideRequirements(file) {
  const lines = [...file.bodyLines];
  for (const req of file.requirements) {
    const start = Math.max(0, req.sectionStart - file.bodyStartLine);
    const end = Math.min(lines.length, req.sectionEnd - file.bodyStartLine);
    for (let index = start; index < end; index++) lines[index] = '';
  }
  return normalizeText(lines.join('\n'));
}

function requirementProse(file, req) {
  const start = Math.max(0, req.sectionStart - file.bodyStartLine);
  const end = Math.min(file.bodyLines.length, req.sectionEnd - file.bodyStartLine);
  return normalizeText(file.bodyLines.slice(start, end).join('\n'));
}

function semanticSnapshot(repo) {
  const terms = new Map();
  const requirements = new Map();
  const relations = new Map();
  const anchors = new Map();

  for (const entity of repo.entities) {
    const file = entity.file;
    const fm = file.frontmatter;
    const id = `${entity.context}.${entity.id}`;
    const properties = Object.fromEntries(Object.entries(fm).filter(([key]) => !OMITTED_PROPERTIES.has(key)));
    terms.set(id, {
      id, context: entity.context, localId: entity.id, kind: entity.kind, name: entity.name, path: entity.path,
      status: fm.status ? String(fm.status) : null,
      properties: canonical(properties),
      prose: proseOutsideRequirements(file),
    });

    for (const link of file.links) {
      const target = qualify(link.ref, entity.context);
      const key = `${id}|${link.relation}|${target}`;
      relations.set(key, { key, from: id, type: link.relation, to: target, context: entity.context });
    }
    for (const anchor of file.frontmatterAnchors) {
      const key = anchorKey(id, anchor);
      anchors.set(key, { key, owner: id, ownerType: 'term', type: anchor.type, target: anchor.target, context: entity.context });
    }

    for (const req of file.requirements) {
      if (!req.id) continue;
      const norms = file.norms
        .filter((norm) => norm.startLine >= req.sectionStart && norm.startLine < req.sectionEnd)
        .map((norm) => normalizeText(norm.sentenceText));
      requirements.set(req.id, {
        id: req.id,
        context: entity.context,
        owner: id,
        path: entity.path,
        kind: req.kindAttr,
        title: req.title,
        subjects: sorted(req.subjects),
        outcomes: sorted(req.outcomes?.values || []),
        partitions: canonical(req.partitions.map((partition) => ({ outcome: partition.outcome, classes: sorted(partition.classes), total: partition.total }))),
        origins: sorted(req.origins || []),
        decidedBy: sorted(req.decidedBy || []),
        norms,
        prose: requirementProse(file, req),
      });
      for (const anchor of req.evidenceAnchors) {
        const key = anchorKey(req.id, anchor);
        anchors.set(key, { key, owner: req.id, ownerType: 'requirement', type: anchor.type, target: anchor.target, context: entity.context });
      }
    }
  }

  const profile = Object.fromEntries(Object.entries(repo.profile).filter(([key]) => key !== 'profile').map(([key, value]) => [key, canonical(value)]));
  return { profile, terms, requirements, relations, anchors };
}

function differencePaths(before, after, prefix) {
  if (stable(before) === stable(after)) return [];
  const beforeObject = before && typeof before === 'object' && !Array.isArray(before);
  const afterObject = after && typeof after === 'object' && !Array.isArray(after);
  if (!beforeObject || !afterObject) return [prefix];
  const keys = sorted([...Object.keys(before), ...Object.keys(after)]);
  return keys.flatMap((key) => differencePaths(before[key], after[key], prefix ? `${prefix}.${key}` : key));
}

function changedFields(before, after, fields) {
  return fields.flatMap((field) => differencePaths(before[field], after[field], field));
}

function mapDiff(before, after, fields = null) {
  const added = [];
  const removed = [];
  const modified = [];
  for (const [key, value] of after) {
    if (!before.has(key)) added.push(value);
    else if (fields) {
      const changes = changedFields(before.get(key), value, fields);
      if (changes.length) modified.push({ before: before.get(key), after: value, fields: changes });
    }
  }
  for (const [key, value] of before) if (!after.has(key)) removed.push(value);
  return { added, removed, modified };
}

function boundaryKind(kind, baseRepo, headRepo) {
  return baseRepo.profile.kinds?.[kind]?.review_role === 'boundary' || headRepo.profile.kinds?.[kind]?.review_role === 'boundary';
}

function collectContexts(diff) {
  const contexts = new Set();
  for (const group of [diff.terms, diff.requirements, diff.relations, diff.anchors]) {
    for (const item of [...group.added, ...group.removed]) if (item.context) contexts.add(item.context);
    for (const item of group.modified || []) if (item.after.context || item.before.context) contexts.add(item.after.context || item.before.context);
  }
  return [...contexts].sort();
}

export function buildSemanticDiff(baseRepo, headRepo, { base = 'base', head = 'worktree' } = {}) {
  const before = semanticSnapshot(baseRepo);
  const after = semanticSnapshot(headRepo);
  const terms = mapDiff(before.terms, after.terms, ['kind', 'name', 'path', 'status', 'properties', 'prose']);
  const requirements = mapDiff(before.requirements, after.requirements, ['owner', 'kind', 'title', 'subjects', 'outcomes', 'partitions', 'origins', 'decidedBy', 'norms', 'prose']);
  const relations = mapDiff(before.relations, after.relations);
  const anchors = mapDiff(before.anchors, after.anchors);
  const profileFields = differencePaths(before.profile, after.profile, '');

  const decisions = [];
  const removedDecisionIds = new Set(terms.removed.filter((term) => term.kind === baseRepo.decisionKind).map((term) => term.id));
  for (const id of removedDecisionIds) {
    const term = before.terms.get(id);
    decisions.push({ severity: term.status === 'принято' ? 'high' : 'medium', code: 'ADR-REMOVED', id, message: 'решение удалено; история должна сохраняться через replaces/revokes' });
  }
  for (const [id, term] of before.terms) {
    if (term.kind !== baseRepo.decisionKind || term.status !== 'принято' || removedDecisionIds.has(id)) continue;
    const areas = [];
    if (terms.modified.some((change) => change.before.id === id)) areas.push('страница');
    if ([...relations.added, ...relations.removed].some((edge) => edge.from === id)) areas.push('relations');
    if ([...anchors.added, ...anchors.removed].some((anchor) => anchor.owner === id)) areas.push('anchors');
    if ([...requirements.added, ...requirements.removed].some((req) => req.owner === id)
      || requirements.modified.some((change) => change.before.owner === id || change.after.owner === id)) areas.push('нормы');
    if (areas.length) decisions.push({ severity: 'high', code: 'ADR-ACCEPTED-MODIFIED', id, message: `принятое решение изменено (${sorted(areas).join(', ')}); требуется новый ADR` });
  }

  const boundaryTerms = [
    ...terms.added.map((term) => ({ change: 'added', term })),
    ...terms.removed.map((term) => ({ change: 'removed', term })),
    ...terms.modified.map((entry) => ({ change: 'modified', term: entry.after, fields: entry.fields })),
  ].filter((entry) => boundaryKind(entry.term.kind, baseRepo, headRepo));
  const boundaryRelations = [...relations.added.map((edge) => ({ change: 'added', edge })), ...relations.removed.map((edge) => ({ change: 'removed', edge }))]
    .filter((entry) => {
      const from = after.terms.get(entry.edge.from) || before.terms.get(entry.edge.from);
      const to = after.terms.get(entry.edge.to) || before.terms.get(entry.edge.to);
      return (from && boundaryKind(from.kind, baseRepo, headRepo)) || (to && boundaryKind(to.kind, baseRepo, headRepo));
    });

  const breaking = terms.removed.length || requirements.removed.length || decisions.some((item) => item.severity === 'high') || boundaryTerms.some((item) => item.change === 'removed') || boundaryRelations.some((item) => item.change === 'removed');
  const significant = terms.added.length || terms.modified.length || requirements.added.length || requirements.modified.length || relations.added.length || relations.removed.length || anchors.added.length || anchors.removed.length || profileFields.length;
  const risk = breaking ? 'high' : significant ? 'medium' : 'low';
  const diff = { base, head, risk, profileFields, terms, requirements, relations, anchors, decisions, boundaries: { terms: boundaryTerms, relations: boundaryRelations } };
  diff.contexts = collectContexts(diff);
  diff.counts = {
    terms: { added: terms.added.length, modified: terms.modified.length, removed: terms.removed.length },
    requirements: { added: requirements.added.length, modified: requirements.modified.length, removed: requirements.removed.length },
    relations: { added: relations.added.length, removed: relations.removed.length },
    anchors: { added: anchors.added.length, removed: anchors.removed.length },
    decisions: decisions.length,
    boundaries: boundaryTerms.length + boundaryRelations.length,
  };
  return diff;
}

export function buildSemanticReview(baseRepo, headRepo, changedFiles, labels = {}) {
  return { semantic: buildSemanticDiff(baseRepo, headRepo, labels), impact: buildReviewImpact(headRepo, changedFiles) };
}

function delta(counts) {
  return `+${counts.added || 0} ~${counts.modified || 0} -${counts.removed || 0}`;
}

function edgeText(edge) {
  return `${edge.from} -[${edge.type}]-> ${edge.to}`;
}

export function formatSemanticReview(report) {
  const { semantic, impact } = report;
  const lines = [
    `SEMANTIC REVIEW: ${semantic.base} → ${semantic.head} · risk ${semantic.risk.toUpperCase()}`,
    `термины ${delta(semantic.counts.terms)} · нормы ${delta(semantic.counts.requirements)} · relations +${semantic.counts.relations.added}/-${semantic.counts.relations.removed} · anchors +${semantic.counts.anchors.added}/-${semantic.counts.anchors.removed}`,
  ];
  if (semantic.profileFields.length) lines.push(`Профиль: изменены ${semantic.profileFields.join(', ')}`);
  if (impact.unmappedFiles.length) {
    lines.push(`Несопоставленные файлы: ${impact.unmappedFiles.length}`);
    for (const file of impact.unmappedFiles) lines.push(`- ${file}`);
  }

  lines.push('', '## Обзор по контекстам');
  if (!semantic.contexts.length && !impact.contexts.length) lines.push('- доменных изменений не найдено');
  for (const context of [...new Set([...semantic.contexts, ...impact.contexts.map((item) => item.id)])].sort()) {
    const route = impact.contexts.find((item) => item.id === context);
    lines.push(`- ${context}: ${route?.terms.length || 0} затронутых терминов, ${route?.requirements.length || 0} затронутых норм`);
  }

  if (semantic.boundaries.terms.length || semantic.boundaries.relations.length) {
    lines.push('', '## Границы');
    for (const item of semantic.boundaries.terms) lines.push(`- [${item.change}] ${item.term.id} (${item.term.kind})${item.fields ? `: ${item.fields.join(', ')}` : ''}`);
    for (const item of semantic.boundaries.relations) lines.push(`- [${item.change}] ${edgeText(item.edge)}`);
  }
  if (semantic.decisions.length) {
    lines.push('', '## Решения');
    for (const item of semantic.decisions) lines.push(`- [${item.severity}] ${item.code} ${item.id} — ${item.message}`);
  }
  if (semantic.terms.added.length || semantic.terms.modified.length || semantic.terms.removed.length) {
    lines.push('', '## Термины');
    for (const item of semantic.terms.added) lines.push(`- [added] ${item.id} (${item.kind})`);
    for (const item of semantic.terms.modified) lines.push(`- [modified] ${item.after.id}: ${item.fields.join(', ')}`);
    for (const item of semantic.terms.removed) lines.push(`- [removed] ${item.id} (${item.kind})`);
  }
  if (semantic.requirements.added.length || semantic.requirements.modified.length || semantic.requirements.removed.length) {
    lines.push('', '## Нормы');
    for (const item of semantic.requirements.added) lines.push(`- [added] ${item.id} — ${item.title} (${item.owner})`, `  → spec.mjs context ${item.id} --slice review`);
    for (const item of semantic.requirements.modified) lines.push(`- [modified] ${item.after.id}: ${item.fields.join(', ')}`, `  → spec.mjs context ${item.after.id} --slice review`);
    for (const item of semantic.requirements.removed) lines.push(`- [removed] ${item.id} — ${item.title} (${item.owner})`, `  → git show ${semantic.base.split('@')[0]}:spec2/${item.path}`);
  }
  if (semantic.relations.added.length || semantic.relations.removed.length) {
    lines.push('', '## Причинность и связи');
    for (const item of semantic.relations.added) lines.push(`- [added] ${edgeText(item)}`);
    for (const item of semantic.relations.removed) lines.push(`- [removed] ${edgeText(item)}`);
  }
  if (semantic.anchors.added.length || semantic.anchors.removed.length) {
    lines.push('', '## Якоря');
    for (const item of semantic.anchors.added) lines.push(`- [added] ${item.owner} → ${item.type}:${item.target}`);
    for (const item of semantic.anchors.removed) lines.push(`- [removed] ${item.owner} → ${item.type}:${item.target}`);
  }

  if (impact.contexts.length) {
    lines.push('', '## Маршрут детального ревью');
    for (const context of impact.contexts) {
      lines.push(`- ${context.id} — ${context.title}`);
      for (const req of context.requirements) lines.push(`  - spec.mjs context ${req.id} --slice review`);
      for (const decision of context.decisions) lines.push(`  - spec.mjs decision ${decision}`);
    }
  }
  return lines.join('\n');
}
