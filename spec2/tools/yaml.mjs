// Единая точка разбора YAML для profile.yaml и Markdown-frontmatter.
// Frontmatter является основным машиночитаемым артефактом, поэтому здесь
// используется полноценный YAML-парсер, а не собственное подмножество.

import YAML from 'yaml';

/**
 * @param {string} text
 * @param {number} [baseLineNo]
 * @returns {*}
 */
export function parseYAML(text, baseLineNo = 1) {
  const document = YAML.parseDocument(text, {
    schema: 'core',
    merge: false,
    uniqueKeys: true,
    maxAliasCount: 0,
    prettyErrors: true,
  });
  if (document.errors.length) {
    const error = document.errors[0];
    const message = error.message.replace(/at line (\d+)/, (_, line) => `at line ${Number(line) + baseLineNo - 1}`);
    throw new Error(message);
  }
  if (document.warnings.length) throw new Error(document.warnings[0].message);
  return document.toJS({ maxAliasCount: 0 });
}

/**
 * @typedef {{ frontmatter: Record<string, *>|null, body: string, bodyStartLine: number,
 *   frontmatterText: string, frontmatterStartLine: number, error: string|null }} FrontmatterResult
 */

/**
 * Разбирает Markdown-файл на единственный YAML-frontmatter и свободное тело.
 * @param {string} fileText
 * @returns {FrontmatterResult}
 */
export function parseFrontmatter(fileText) {
  const lines = fileText.split(/\r?\n/);
  if (lines[0] !== '---') {
    return { frontmatter: null, body: fileText, bodyStartLine: 1, frontmatterText: '', frontmatterStartLine: 1, error: 'нет frontmatter' };
  }
  const end = lines.indexOf('---', 1);
  if (end === -1) {
    return { frontmatter: null, body: fileText, bodyStartLine: 1, frontmatterText: '', frontmatterStartLine: 1, error: 'frontmatter не закрыт' };
  }
  const frontmatterText = lines.slice(1, end).join('\n');
  const body = lines.slice(end + 1).join('\n');
  try {
    const frontmatter = parseYAML(frontmatterText, 2);
    if (!frontmatter || typeof frontmatter !== 'object' || Array.isArray(frontmatter)) {
      return { frontmatter: null, body, bodyStartLine: end + 2, frontmatterText, frontmatterStartLine: 2, error: 'frontmatter должен быть объектом' };
    }
    return { frontmatter, body, bodyStartLine: end + 2, frontmatterText, frontmatterStartLine: 2, error: null };
  } catch (error) {
    return { frontmatter: null, body, bodyStartLine: end + 2, frontmatterText, frontmatterStartLine: 2, error: `ошибка разбора: ${error.message}` };
  }
}
