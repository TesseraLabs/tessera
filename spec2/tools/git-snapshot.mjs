import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { loadRepo } from './graph.mjs';

function git(productRoot, args, options = {}) {
  return execFileSync('git', args, { cwd: productRoot, ...options });
}

function validateRef(ref) {
  const value = String(ref || '');
  if (!value || value.startsWith('-') || /[\0\r\n]/u.test(value)) throw new Error(`недопустимый Git-ref: ${JSON.stringify(value)}`);
  return value;
}

export function changedFilesBetween(productRoot, base, head = null) {
  base = validateRef(base);
  if (head) head = validateRef(head);
  const args = head ? ['diff', '--name-only', base, head] : ['diff', '--name-only', base];
  const tracked = git(productRoot, args, { encoding: 'utf8' }).split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (head) return [...new Set(tracked)].sort();
  const untracked = git(productRoot, ['ls-files', '--others', '--exclude-standard'], { encoding: 'utf8' })
    .split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  return [...new Set([...tracked, ...untracked])].sort();
}

/** Материализует spec2 из Git-ref без checkout и без изменения worktree. */
export function loadRepoAtGitRef(productRoot, ref) {
  ref = validateRef(ref);
  const commit = git(productRoot, ['rev-parse', '--verify', `${ref}^{commit}`], { encoding: 'utf8' }).trim();
  try {
    git(productRoot, ['cat-file', '-e', `${commit}:spec2/profile.yaml`]);
  } catch {
    throw new Error(`Git-ref ${ref} (${commit.slice(0, 12)}) не содержит spec2/profile.yaml`);
  }

  const tempProductRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tessera-spec2-ref-'));
  try {
    const archive = git(productRoot, ['archive', '--format=tar', commit, 'spec2'], { maxBuffer: 100 * 1024 * 1024 });
    execFileSync('tar', ['-xf', '-', '-C', tempProductRoot], { input: archive, maxBuffer: 100 * 1024 * 1024 });
    const repo = loadRepo(path.join(tempProductRoot, 'spec2'), productRoot);
    return {
      ref,
      commit,
      repo,
      cleanup: () => fs.rmSync(tempProductRoot, { recursive: true, force: true }),
    };
  } catch (error) {
    fs.rmSync(tempProductRoot, { recursive: true, force: true });
    throw error;
  }
}
