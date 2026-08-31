import test from 'node:test';
import assert from 'node:assert/strict';
import { extractOutcomes } from './python.mjs';

test('extractOutcomes (py): подкласс enum.Enum — declared из членов, confidence exact', () => {
  const source = [
    'import enum',
    '',
    'class Status(enum.Enum):',
    '    REVOKED = "revoked"',
    '    VALID = auto()',
  ].join('\n');
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['REVOKED', 'VALID']);
  assert.equal(r.confidence, 'exact');
});

test('extractOutcomes (py): typing.Literal[...] в аннотации возврата', () => {
  const source = [
    'from typing import Literal',
    '',
    "def check(id: str) -> Literal['ok', 'notFound']:",
    "    if not id:",
    "        raise NotFoundError(id)",
    "    return 'ok'",
  ].join('\n');
  const r = extractOutcomes(source, 'check');
  assert.deepEqual(r.declared, ['ok', 'notFound']);
  assert.equal(r.confidence, 'syntactic');
  assert.deepEqual(r.escaping, ['raise NotFoundError']);
});

test('extractOutcomes (py): -> A | Optional[X] и голый raise/assert', () => {
  const source = [
    'class Extra(enum.Enum):',
    '    X = 1',
    '',
    'def find(id: str) -> Extra | None:',
    '    assert id, "id required"',
    '    try:',
    '        return lookup(id)',
    '    except KeyError:',
    '        raise',
  ].join('\n');
  const r = extractOutcomes(source, 'find');
  assert.deepEqual(r.declared, ['X', 'None']);
  assert.ok(r.escaping.includes('raise'));
  assert.ok(r.escaping.some((s) => s.startsWith('assert ')));
});

test('extractOutcomes (py): raise через динамическое выражение — unresolved, не теряется', () => {
  const source = [
    'def dispatch(key: str) -> None:',
    '    raise errors[key]',
  ].join('\n');
  const r = extractOutcomes(source, 'dispatch');
  assert.deepEqual(r.escaping, []);
  assert.ok(r.unresolved.some((u) => u.includes('errors[key]')));
});

test('extractOutcomes (py): функция без аннотации возврата — confidence shallow (норма для Python)', () => {
  const source = [
    'def untyped(x):',
    '    return x + 1',
  ].join('\n');
  const r = extractOutcomes(source, 'untyped');
  assert.equal(r.confidence, 'shallow');
  assert.deepEqual(r.declared, []);
});

test('extractOutcomes (py): значимые отступы — тело определяется не скобками', () => {
  const source = [
    'def outer(x: int) -> None:',
    '    if x > 0:',
    '        raise ValueError("positive")',
    '    return None',
    '',
    'def sibling():',
    '    raise RuntimeError("should not be included")',
  ].join('\n');
  const r = extractOutcomes(source, 'outer');
  assert.deepEqual(r.escaping, ['raise ValueError']);
});

test('extractOutcomes (py): символ не найден — null', () => {
  const source = 'def foo():\n    pass\n';
  assert.equal(extractOutcomes(source, 'nope'), null);
});
