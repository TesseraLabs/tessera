import YAML from 'yaml';

function placeholderFor(field, profile, kindDef) {
  if (field.startsWith('relations.')) {
    const relation = field.slice('relations.'.length);
    const target = 'TODO:context.id';
    return profile.relation_types?.[relation]?.cardinality === 'many' ? [target] : target;
  }
  if (field === 'owner') return 'TODO:context';
  if (field === 'status' && Array.isArray(kindDef.lifecycle) && kindDef.lifecycle.length > 0) return kindDef.lifecycle[0];
  if (field === 'date') return new Date().toISOString().slice(0, 10);
  if (field === 'entrypoint') return 'TODO:path#symbol';
  if (field === 'source') return 'TODO:source';
  if (field === 'reload') return 'TODO:reload-policy';
  if (field === 'format') return 'TODO:format';
  if (field === 'compatibility') return 'TODO:compatibility-rule';
  return `TODO:${field}`;
}

function setPath(target, dottedPath, value) {
  const parts = dottedPath.split('.');
  let current = target;
  for (const part of parts.slice(0, -1)) {
    current[part] ??= {};
    current = current[part];
  }
  current[parts.at(-1)] = value;
}

/**
 * Печатает profile-aware заготовку, но не записывает её: доменные связи,
 * требования и смысл остаются решением автора.
 */
export function draftPage(repo, kind, qualifiedId, name = 'TODO: название') {
  const dot = qualifiedId.indexOf('.');
  if (dot <= 0 || dot === qualifiedId.length - 1) {
    throw new Error('id заготовки должен иметь вид context.id');
  }
  const context = qualifiedId.slice(0, dot);
  const id = qualifiedId.slice(dot + 1);
  const kindDef = repo.profile.kinds?.[kind];
  if (!kindDef) throw new Error(`неизвестный kind "${kind}"`);
  if (!repo.profile.contexts?.[context]) throw new Error(`неизвестный context "${context}"`);
  if (repo.entities.some((entity) => entity.id === id && entity.context === context)) {
    throw new Error(`термин "${qualifiedId}" уже существует`);
  }

  const frontmatter = { id, kind, context, name };
  for (const field of kindDef.required_fields || []) {
    setPath(frontmatter, field, placeholderFor(field, repo.profile, kindDef));
  }

  frontmatter.relations ??= {};
  for (const must of kindDef.must || []) {
    if (must === 'outcomes') frontmatter.outcomes = ['TODO: основной исход', 'TODO: отказ'];
    if (must === 'producer') frontmatter.relations.producer = 'TODO:context.operation';
  }

  const requiredAnchors = kindDef.anchors?.required || [];
  if (requiredAnchors.length > 0) {
    frontmatter.anchors = Object.fromEntries(
      requiredAnchors.map((anchorType) => [anchorType, [`TODO:${anchorType}:path#symbol`]]),
    );
  }

  const yaml = YAML.stringify(frontmatter, { lineWidth: 0 }).trimEnd();
  const sections = ['Purpose', ...(kindDef.required_sections || [])];
  const uniqueSections = [...new Set(sections)];
  const body = [
    `# ${name}`,
    ...uniqueSections.flatMap((section) => ['', `## ${section}`, '', 'TODO']),
  ].join('\n');
  return `---\n${yaml}\n---\n\n${body}\n`;
}
