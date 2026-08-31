import fs from 'node:fs';
import path from 'node:path';
import rustAdapter, { extractOutcomes } from './adapters/rust.mjs';

const resolverCache = new Map();

function rustFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['target', 'vendor', '.git'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...rustFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.rs')) out.push(full);
  }
  return out;
}

function crateOf(file) {
  const match = /^crates\/([^/]+)\//.exec(file);
  return match?.[1] || null;
}

function importHint(source, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`use\\s+([^;]*\\b${escaped}\\b[^;]*);`, 's').exec(source);
  if (!match) return null;
  const raw = match[1].replace(/\s+/g, ' ');
  const prefix = raw.includes('{') ? raw.slice(0, raw.indexOf('{')).replace(/::$/, '') : raw.replace(new RegExp(`::${escaped}(?:\\s+as\\s+\\w+)?$`), '');
  return prefix.trim();
}

/** Индекс публичных Rust types с best-effort разрешением use-path. */
export function buildRustWorkspaceResolver(productRoot) {
  const cacheKey = path.resolve(productRoot);
  if (resolverCache.has(cacheKey)) return resolverCache.get(cacheKey);
  const index = new Map();
  for (const abs of rustFiles(path.join(productRoot, 'crates'))) {
    const file = path.relative(productRoot, abs).split(path.sep).join('/');
    const source = fs.readFileSync(abs, 'utf8');
    for (const type of rustAdapter.extractPublicTypes(source)) {
      if (!index.has(type.name)) index.set(type.name, []);
      index.get(type.name).push({ ...type, file, source, crate: crateOf(file) });
    }
  }

  const resolver = function resolveType(name, { sourceFile = '', source = '' } = {}) {
    let candidates = index.get(name) || [];
    if (candidates.length === 0) return null;
    const hint = importHint(source, name);
    const currentCrate = crateOf(sourceFile);
    if (hint) {
      const parts = hint.split('::').filter(Boolean);
      const hintedCrate = ['crate', 'self', 'super'].includes(parts[0]) ? currentCrate : parts[0];
      const byCrate = candidates.filter((item) => item.crate === hintedCrate);
      if (byCrate.length) candidates = byCrate;
      const modules = parts.slice(['crate', 'self', 'super'].includes(parts[0]) ? 1 : 1);
      candidates = candidates
        .map((item) => ({ item, score: modules.reduce((score, segment) => score + (item.file.includes(`/${segment}/`) || item.file.includes(`/${segment}.rs`) ? 1 : 0), 0) }))
        .sort((a, b) => b.score - a.score || a.item.file.localeCompare(b.item.file));
      if (candidates.length > 1 && candidates[0].score === candidates[1].score) return null;
      candidates = candidates.map((entry) => entry.item);
    } else if (candidates.length > 1) {
      const local = candidates.filter((item) => item.crate === currentCrate);
      if (local.length === 1) candidates = local;
      else return null;
    }
    const chosen = candidates[0];
    if (!chosen) return null;
    if (chosen.kind === 'struct') return { kind: 'struct', file: chosen.file };
    const variants = extractOutcomes(chosen.source, name)?.declared || [];
    return { kind: 'enum', variants, file: chosen.file };
  };
  resolverCache.set(cacheKey, resolver);
  return resolver;
}
