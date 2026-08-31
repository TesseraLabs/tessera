const QUALITY_CODES = new Set([
  'W-GENERIC-NORM',
  'W-SELF-ONLY-SUBJECT',
  'W-COARSE-EVIDENCE',
  'W-BROAD-CODE-ANCHOR',
  'W-UNRESOLVED-CLAIM',
]);

export function isQualityCode(code) {
  return QUALITY_CODES.has(code);
}

function row(code, severity, file, line, requirement, message, action) {
  return { code, severity, path: file.path, line, requirement, message, action };
}

/** Сигналы семантической слабости, которые не являются синтаксическими ошибками. */
export function buildQualityReport(repo) {
  const rows = [];
  for (const file of repo.files) {
    const fm = file.frontmatter;
    if (!fm?.id || !fm?.context) continue;
    const owner = `${fm.context}.${fm.id}`;

    for (const req of file.requirements) {
      if (!req.id) continue;
      if (['операция', 'процесс'].includes(String(fm.kind)) && req.subjects.length === 1 && req.subjects[0] === owner) {
        rows.push(row('W-SELF-ONLY-SUBJECT', 'medium', file, req.headingLine, req.id,
          `норма ${req.id} привязана только к владельцу ${owner}; доменная сущность, контракт или конфигурация не названы`,
          `spec.mjs context ${req.id} --slice implement`));
      }

      const sentences = file.norms.filter((norm) => norm.startLine >= req.sectionStart && norm.startLine < req.sectionEnd);
      // В JavaScript `\b` знает только ASCII-слово, поэтому вокруг русских
      // слов граница не срабатывает. Оставляем её только перед RFC-оператором.
      if (sentences.some((norm) => /\bMUST\s+соблюдать\s+правило[\s\S]*условиями/i.test(norm.sentenceText))) {
        rows.push(row('W-GENERIC-NORM', 'medium', file, req.headingLine, req.id,
          `норма ${req.id} использует миграционную оболочку вместо самостоятельного предиката`,
          `открыть ${file.path}#${req.id}`));
      }

      const tests = req.evidenceAnchors.filter((anchor) => anchor.type === 'test');
      if (tests.length > 0 && tests.every((anchor) => !anchor.symbol)) {
        rows.push(row('W-COARSE-EVIDENCE', 'medium', file, req.headingLine, req.id,
          `test evidence нормы ${req.id} указывает только на файл, без #CASE-ID или символа`,
          `spec.mjs e2e --missing; затем уточнить test:...#CASE-ID для ${req.id}`));
      }

      const broadCode = req.evidenceAnchors.filter((anchor) => anchor.type === 'code' && !anchor.symbol);
      if (broadCode.length > 0) {
        rows.push(row('W-BROAD-CODE-ANCHOR', 'low', file, req.headingLine, req.id,
          `code evidence нормы ${req.id} не указывает символ: ${broadCode.map((anchor) => anchor.target).join(', ')}`,
          `уточнить code:...#symbol в ${file.path}`));
      }
    }

    const broadPageCode = file.frontmatterAnchors.filter((anchor) => anchor.type === 'code' && !anchor.symbol);
    if (broadPageCode.length > 0) {
      rows.push(row('W-BROAD-CODE-ANCHOR', 'low', file, file.frontmatterStartLine, null,
        `code-якорь страницы не указывает символ: ${broadPageCode.map((anchor) => anchor.target).join(', ')}`,
        `уточнить anchors.code в ${file.path}`));
    }

    const claimPattern = /\bKNOWN GAP\b|\bTBD\b|не\s+реализован[аоы]?|проверя(?:ется|ются)\s+вручную|#\[ignore\]/iu;
    const claimedRequirements = new Set();
    for (let index = 0; index < file.maskedLines.length; index++) {
      const text = file.maskedLines[index];
      if (!claimPattern.test(text)) continue;
      const line = file.bodyStartLine + index;
      const requirement = file.requirements.find((req) => line >= req.sectionStart && line < req.sectionEnd) || null;
      // Заголовок, нормативное предложение и миграционная заметка часто
      // повторяют один KNOWN GAP. Это одна задача на норму, а не три.
      if (requirement && claimedRequirements.has(requirement.id)) continue;
      if (requirement) claimedRequirements.add(requirement.id);
      rows.push(row('W-UNRESOLVED-CLAIM', 'high', file, line, requirement?.id || null,
        `утверждение требует явного решения, ADR или удаления как устаревшего: ${text.trim().slice(0, 180)}`,
        `проверить утверждение в ${file.path}:${line}`));
    }
  }

  const counts = {};
  const severityCounts = { high: 0, medium: 0, low: 0 };
  for (const code of QUALITY_CODES) counts[code] = 0;
  for (const item of rows) {
    counts[item.code]++;
    severityCounts[item.severity]++;
  }
  return { total: rows.length, counts, severityCounts, rows };
}

export function formatQualityReport(report, { all = false } = {}) {
  const lines = [
    `Quality: ${report.total} сигналов (${report.severityCounts.high} high / ${report.severityCounts.medium} medium / ${report.severityCounts.low} low)`,
  ];
  for (const [code, count] of Object.entries(report.counts)) lines.push(`- ${code}: ${count}`);
  if (!all) {
    if (report.total) lines.push('', 'Детализация: spec.mjs quality --all');
    return lines.join('\n');
  }
  for (const item of [...report.rows].sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line)) {
    lines.push(`- [${item.severity}] ${item.code} ${item.path}:${item.line}${item.requirement ? ` (${item.requirement})` : ''}`, `  ${item.message}`, `  → ${item.action}`);
  }
  return lines.join('\n');
}
