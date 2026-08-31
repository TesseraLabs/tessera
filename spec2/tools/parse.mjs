// Frontmatter-first parser. Markdown carries explanation and scenarios;
// identity, relations, requirements, evidence and outcome models live in YAML.

import fs from 'node:fs';
import path from 'node:path';
import { parseFrontmatter } from './yaml.mjs';
import {
  maskZones, findLinks, findLinksInText, findHeadings, findOperators,
  findRuOperators, splitSentences, buildOffsetToLine,
} from './markdown.mjs';

export function findSpecFiles(root, sources) {
  const files = [];
  const warnings = [];
  const relative = (value) => path.relative(root, value).split(path.sep).join('/') || '.';
  function walk(directory) {
    let entries;
    try { entries = fs.readdirSync(directory, { withFileTypes: true }); }
    catch (error) { warnings.push({ path: relative(directory), reason: `не удалось прочитать директорию: ${error.message}` }); return; }
    for (const entry of entries) {
      const full = path.join(directory, entry.name);
      let isDirectory = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        try { const stat = fs.statSync(full); isDirectory = stat.isDirectory(); isFile = stat.isFile(); }
        catch (error) { warnings.push({ path: relative(full), reason: `битый симлинк или недоступная цель: ${error.message}` }); continue; }
      }
      if (isDirectory) walk(full);
      else if (isFile && entry.name.endsWith('.md')) files.push(full);
    }
  }
  for (const source of Array.isArray(sources) ? sources : []) walk(path.join(root, source));
  return { files: files.sort(), warnings };
}

const ANCHOR_TYPES = new Set(['code', 'test', 'schema', 'exemplar', 'counterexample', 'type']);

function makeAnchor(type, target) {
  const text = String(target).trim();
  const hash = text.indexOf('#');
  return { type, target: text, file: hash === -1 ? text : text.slice(0, hash), symbol: hash === -1 ? null : text.slice(hash + 1) };
}

function groupedAnchors(value, unparsed = []) {
  const anchors = [];
  if (value === undefined) return anchors;
  if (!value || typeof value !== 'object' || Array.isArray(value)) { unparsed.push(value); return anchors; }
  for (const [type, targets] of Object.entries(value)) {
    if (!ANCHOR_TYPES.has(type) || !Array.isArray(targets)) { unparsed.push({ [type]: targets }); continue; }
    for (const target of targets) anchors.push(makeAnchor(type, target));
  }
  return anchors;
}

function sectionEndLine(headings, index, eofLine) {
  const current = headings[index];
  for (let next = index + 1; next < headings.length; next++) if (headings[next].level <= current.level) return headings[next].line;
  return eofLine + 1;
}

function looksLikeInfinitive(word) { return /[A-Za-zА-Яа-яЁё]*(?:ть|ти|чь)$/.test(word); }
const VERB_COORD_RE = /([A-Za-zА-Яа-яЁё]+)\s+(?:и|либо)\s+((?:[A-Za-zА-Яа-яЁё]+\s+){0,2}[A-Za-zА-Яа-яЁё]+)/g;
function hasVerbCoordination(text) {
  VERB_COORD_RE.lastIndex = 0;
  let match;
  while ((match = VERB_COORD_RE.exec(text))) if (looksLikeInfinitive(match[1]) && match[2].trim().split(/\s+/).some(looksLikeInfinitive)) return true;
  return false;
}

function analyzeNorms(maskedLines, bodyStartLine) {
  const text = maskedLines.join('\n');
  const offsetToLine = buildOffsetToLine(text, bodyStartLine);
  const result = [];
  for (const span of splitSentences(text)) {
    const sentenceText = text.slice(span.start, span.end);
    const foundOperators = findOperators(sentenceText);
    if (!foundOperators.length) continue;
    const links = findLinksInText(sentenceText).map((link) => ({ ...link, line: offsetToLine(span.start + link.index) }));
    result.push({
      startLine: offsetToLine(span.start), endLine: offsetToLine(span.end), sentenceText,
      hasCoordination: foundOperators.length >= 2 || hasVerbCoordination(sentenceText), allLinksInSentence: links,
      operators: foundOperators.map((operator) => {
        const preceding = links.filter((link) => link.index < operator.index).pop() || null;
        return { op: operator.op, line: offsetToLine(span.start + operator.index), hasPrecedingLink: !!preceding, precedingLink: preceding };
      }),
    });
  }
  return result;
}

function valueLine(frontmatterText, frontmatterStartLine, key) {
  const lines = frontmatterText.split(/\r?\n/);
  const escaped = String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const index = lines.findIndex((line) => new RegExp(`^\\s*${escaped}:`).test(line));
  return index === -1 ? frontmatterStartLine : frontmatterStartLine + index;
}

function parseRequirements(data, headings, eofLine, fm) {
  if (!data.requirements || typeof data.requirements !== 'object' || Array.isArray(data.requirements)) return [];
  return Object.entries(data.requirements).map(([id, raw]) => {
    const metadata = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    const headingIndex = headings.findIndex((heading) => heading.text.startsWith(`${id} — `) || heading.text.startsWith(`${id} - `));
    const heading = headings[headingIndex] || null;
    const unparsedEvidenceAnchors = [];
    const rawDecidedBy = metadata.decided_by;
    const decidedBy = Array.isArray(rawDecidedBy) ? rawDecidedBy.filter((value) => typeof value === 'string').map(String) : [];
    const unparsedDecidedBy = rawDecidedBy === undefined
      ? []
      : Array.isArray(rawDecidedBy) ? rawDecidedBy.filter((value) => typeof value !== 'string') : [rawDecidedBy];
    return {
      id, kindAttr: metadata.kind ? String(metadata.kind) : null,
      subjects: Array.isArray(metadata.subjects) ? metadata.subjects.map(String) : [],
      isCanonical: data.kind !== 'паттерн', missingId: false, missingHeading: !heading,
      title: heading ? heading.text.replace(new RegExp(`^${id}\\s+[—-]\\s+`), '') : id,
      headingLine: heading?.line ?? valueLine(fm.frontmatterText, fm.frontmatterStartLine, id),
      headingLevel: heading?.level ?? 0, sectionStart: heading?.line ?? fm.bodyStartLine,
      sectionEnd: heading ? sectionEndLine(headings, headingIndex, eofLine) : fm.bodyStartLine,
      evidenceAnchors: groupedAnchors(metadata.evidence, unparsedEvidenceAnchors), unparsedEvidenceAnchors,
      origins: Array.isArray(metadata.origins) ? metadata.origins.filter((value) => typeof value === 'string').map(String) : [],
      decidedBy, unparsedDecidedBy,
      outcomes: Array.isArray(metadata.outcomes) ? { values: metadata.outcomes.map(String), closed: true, line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, id) } : null,
      partitions: Array.isArray(metadata.partitions) ? metadata.partitions.map((partition) => ({
        outcome: String(partition.outcome || ''), classes: Array.isArray(partition.classes) ? partition.classes.map(String) : [],
        total: partition.total === true, line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, id),
      })) : [],
    };
  });
}

function parseRelations(data, fm) {
  if (!data.relations || typeof data.relations !== 'object' || Array.isArray(data.relations)) return [];
  const result = [];
  for (const [relation, raw] of Object.entries(data.relations)) {
    for (const target of Array.isArray(raw) ? raw : [raw]) {
      if (typeof target === 'string') result.push({ ref: target, relation, line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, relation), zone: 'frontmatter' });
    }
  }
  return result;
}

function parseConformance(data, fm) {
  if (!data.conformance || typeof data.conformance !== 'object' || Array.isArray(data.conformance)) return [];
  const result = [];
  for (const [key, evidence] of Object.entries(data.conformance)) {
    const match = /^([\w-]+)\/([\w-]+)$/.exec(key);
    if (!match) continue;
    result.push({ pattern: match[1], normId: match[2], anchors: groupedAnchors(evidence), line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, key) });
  }
  return result;
}

function parseCombinations(data, fm) {
  if (!Array.isArray(data.combinations)) return [];
  return data.combinations.map((table) => {
    const dimensions = table?.dimensions && typeof table.dimensions === 'object' ? table.dimensions : {};
    const line = valueLine(fm.frontmatterText, fm.frontmatterStartLine, 'combinations');
    const dims = Object.entries(dimensions).map(([name, values]) => ({ name, values: Array.isArray(values) ? values.map(String) : [], line }));
    const rows = Array.isArray(table?.rows) ? table.rows.map((row, index) => ({
      line, num: String(index + 1), dimValues: dims.map((dimension) => String(row.when?.[dimension.name] ?? '')),
      outcomeRaw: String(row.note ?? row.outcome ?? ''), outcome: row.outcome === null ? null : String(row.outcome),
      undefined: row.outcome === null, columnMismatch: false,
    })) : [];
    return { dims, rows, sectionLine: line, unparsedDimLines: [] };
  });
}

export function parseSpecFile(absPath, root) {
  const raw = fs.readFileSync(absPath, 'utf8');
  const relPath = path.relative(root, absPath).split(path.sep).join('/');
  const fm = parseFrontmatter(raw);
  const data = fm.frontmatter || {};
  const bodyLines = fm.body.split(/\r?\n/);
  const maskedLines = maskZones(bodyLines);
  const eofLine = fm.bodyStartLine + bodyLines.length - 1;
  const headings = findHeadings(maskedLines, fm.bodyStartLine);
  const unparsedFrontmatterAnchors = [];
  return {
    path: relPath, absPath, raw, frontmatter: fm.frontmatter, frontmatterError: fm.error,
    frontmatterText: fm.frontmatterText, frontmatterStartLine: fm.frontmatterStartLine,
    bodyStartLine: fm.bodyStartLine, bodyLines, maskedLines, headings,
    requirements: parseRequirements(data, headings, eofLine, fm),
    links: parseRelations(data, fm),
    navigationLinks: findLinks(maskedLines, fm.bodyStartLine).map((link) => ({ ...link, zone: 'body' })),
    ruOperators: findRuOperators(maskedLines, fm.bodyStartLine), norms: analyzeNorms(maskedLines, fm.bodyStartLine),
    conformance: parseConformance(data, fm),
    frontmatterAnchors: groupedAnchors(data.anchors, unparsedFrontmatterAnchors), unparsedFrontmatterAnchors,
    outcomesBlocks: Array.isArray(data.outcomes) ? [{ values: data.outcomes.map(String), closed: true, line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, 'outcomes') }] : [],
    partitionBlocks: Array.isArray(data.partitions) ? data.partitions.map((partition) => ({
      outcome: String(partition.outcome || ''), classes: Array.isArray(partition.classes) ? partition.classes.map(String) : [],
      total: partition.total === true, line: valueLine(fm.frontmatterText, fm.frontmatterStartLine, 'partitions'),
    })) : [],
    combinations: parseCombinations(data, fm),
  };
}
