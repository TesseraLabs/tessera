import { resolveAnchor, resolveLink } from './graph.mjs';

function qualified(entity) {
  return `${entity.context}.${entity.id}`;
}

function evidenceGap(req, profile) {
  const spec = profile.norm_kinds?.[req.kindAttr];
  if (!spec || !Array.isArray(spec.evidence) || spec.evidence.length === 0) return null;
  const present = new Set(req.evidenceAnchors.map((anchor) => anchor.type));
  const satisfied = spec.any_of
    ? spec.evidence.some((type) => present.has(type))
    : spec.evidence.every((type) => present.has(type));
  if (satisfied) return null;
  return spec.any_of
    ? `missing-evidence:any-of(${spec.evidence.join(',')})`
    : `missing-evidence:all-of(${spec.evidence.join(',')})`;
}

function implementationAnchors(entity) {
  const implementationTypes = new Set(['code', 'type', 'schema', 'exemplar']);
  return entity.file.frontmatterAnchors.filter((anchor) => implementationTypes.has(anchor.type));
}

function hasDeclaredNoImplementationAnchor(entity) {
  const noAnchor = entity.file.frontmatter?.no_anchor;
  if (!noAnchor || typeof noAnchor !== 'object' || Array.isArray(noAnchor)) return false;
  return ['code', 'type', 'schema', 'exemplar'].some((type) => {
    const reason = noAnchor[type];
    return typeof reason === 'string' && reason.trim() !== '';
  });
}

function targetPredicate(repo, target) {
  if (!target) return () => true;
  if (repo.requirementsById.has(target)) return ({ id }) => id === target;

  let entity = null;
  const dot = target.indexOf('.');
  if (dot !== -1) {
    entity = repo.entitiesByContextId.get(`${target.slice(0, dot)} ${target.slice(dot + 1)}`) || null;
  } else {
    const candidates = repo.entitiesById.get(target) || [];
    if (candidates.length > 1) throw new Error(`термин "${target}" неоднозначен; используйте context.id`);
    entity = candidates[0] || null;
  }
  if (!entity) throw new Error(`норма или термин "${target}" не найдены`);
  const entityId = qualified(entity);
  return (row) => row.owner.id === entityId || row.subjects.some((subject) => subject.id === entityId);
}

/**
 * Каноническая трассировочная матрица. Шаблонные нормы паттернов не включаются:
 * их evidence существует только после применения и показывается conformance.
 */
export function buildTrace(repo, { target = null, missingOnly = false } = {}) {
  const rows = [];
  for (const file of repo.files) {
    const fm = file.frontmatter;
    if (!fm?.id || !fm?.context) continue;
    const ownerEntity = repo.entitiesByContextId.get(`${fm.context} ${fm.id}`);
    if (!ownerEntity) continue;
    for (const req of file.requirements) {
      if (!req.id || !req.isCanonical) continue;
      const gaps = [];
      if (req.subjects.length === 0) gaps.push('no-subject');

      const subjects = req.subjects.map((ref) => {
        const resolution = resolveLink({ ref }, String(fm.context), repo);
        if (!resolution.target) {
          gaps.push(`unresolved-subject:${ref}`);
          return { id: ref, kind: null, path: null, anchors: [], resolved: false };
        }
        const entity = resolution.target;
        const anchors = implementationAnchors(entity).map((anchor) => ({
          type: anchor.type,
          target: anchor.target,
          ok: resolveAnchor(anchor, repo.productRoot).ok,
        }));
        if (anchors.length === 0 && !hasDeclaredNoImplementationAnchor(entity)) {
          gaps.push(`no-implementation-anchor:${qualified(entity)}`);
        }
        return { id: qualified(entity), kind: entity.kind, path: entity.path, anchors, resolved: true };
      });

      const evidence = req.evidenceAnchors.map((anchor) => {
        const resolution = resolveAnchor(anchor, repo.productRoot);
        if (!resolution.ok) gaps.push(`broken-evidence:${anchor.target}`);
        return { type: anchor.type, target: anchor.target, ok: resolution.ok };
      });
      const missingEvidence = evidenceGap(req, repo.profile);
      if (missingEvidence) gaps.push(missingEvidence);

      rows.push({
        id: req.id,
        title: req.title,
        kind: req.kindAttr,
        owner: { id: qualified(ownerEntity), kind: ownerEntity.kind, path: file.path },
        decisions: req.decidedBy || [],
        subjects,
        evidence,
        outcomes: req.outcomes?.values || [],
        gaps: [...new Set(gaps)],
      });
    }
  }

  const matchesTarget = targetPredicate(repo, target);
  return rows
    .filter(matchesTarget)
    .filter((row) => !missingOnly || row.gaps.length > 0)
    .sort((a, b) => a.id.localeCompare(b.id));
}

function cell(value) {
  const text = Array.isArray(value) ? value.join('<br>') : String(value ?? '');
  return (text || '—').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function formatTrace(rows, { missingOnly = false } = {}) {
  if (rows.length === 0) return missingOnly ? 'Дыр трассировки не найдено.' : 'Нормы не найдены.';
  const lines = [
    '| Норма | Kind | Владелец | Decisions | Subjects | Evidence | Реализация субъектов | Outcomes | Gaps |',
    '|---|---|---|---|---|---|---|---|---|',
  ];
  for (const row of rows) {
    const subjects = row.subjects.map((subject) => `${subject.id}${subject.kind ? ` (${subject.kind})` : ' (не разрешён)'}`);
    const evidence = row.evidence.map((anchor) => `${anchor.ok ? '✓' : '✗'} ${anchor.type}:${anchor.target}`);
    const implementation = row.subjects.flatMap((subject) => subject.anchors.map(
      (anchor) => `${anchor.ok ? '✓' : '✗'} ${subject.id} → ${anchor.type}:${anchor.target}`,
    ));
    lines.push(`| ${cell(`${row.id} — ${row.title}`)} | ${cell(row.kind)} | ${cell(row.owner.id)} | ${cell(row.decisions)} | ${cell(subjects)} | ${cell(evidence)} | ${cell(implementation)} | ${cell(row.outcomes)} | ${cell(row.gaps)} |`);
  }
  return lines.join('\n');
}
