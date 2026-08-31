import test from 'node:test';
import assert from 'node:assert/strict';
import { extractOutcomes, extractPublicTypes } from './rust.mjs';

test('extractOutcomes (rust): enum — declared из вариантов, confidence exact', () => {
  const source = 'pub enum Status {\n    Revoked,\n    Valid,\n}\n';
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['Revoked', 'Valid']);
  assert.deepEqual(r.escaping, []);
  assert.equal(r.confidence, 'exact');
  assert.deepEqual(r.unresolved, []);
});

test('extractOutcomes (rust): функция, возвращающая enum — declared развёрнут, escaping из паники/unwrap/expect/индексации', () => {
  const source = [
    'pub enum Outcome { Ok, Bad }',
    '',
    'pub fn check(items: &[u8]) -> Outcome {',
    '    if items.is_empty() { panic!("empty"); }',
    '    let first = items.get(0).unwrap();',
    '    let second = items.get(1).expect("missing");',
    '    let third = items[2];',
    '    Outcome::Ok',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'check');
  assert.deepEqual(r.declared, ['Ok', 'Bad']);
  assert.equal(r.confidence, 'syntactic');
  assert.ok(r.escaping.includes('panic!'));
  assert.ok(r.escaping.includes('.unwrap()'));
  assert.ok(r.escaping.includes('.expect('));
  assert.ok(r.escaping.some((s) => s.includes('items[2]')));
  assert.deepEqual(r.unresolved, []);
});

test('extractOutcomes (rust): функция без именованного типа возврата — unresolved и confidence shallow', () => {
  const source = 'pub fn helper() -> u32 {\n    42\n}\n';
  const r = extractOutcomes(source, 'helper');
  assert.deepEqual(r.declared, []);
  assert.equal(r.confidence, 'shallow');
  assert.ok(r.unresolved.length > 0);
});

test('extractOutcomes (rust): bool и Result с локальной enum ошибки имеют структурные исходы', () => {
  const source = [
    'pub enum ParseError { Empty, Invalid { at: usize } }',
    'pub fn parse(s: &str) -> Result<u32, ParseError> { todo!() }',
    'pub fn matches(a: u8, b: u8) -> bool { a == b }',
  ].join('\n');
  const parsed = extractOutcomes(source, 'parse');
  assert.deepEqual(parsed.declared, ['Ok', 'Err::Empty', 'Err::Invalid']);
  assert.equal(parsed.confidence, 'syntactic');
  assert.deepEqual(parsed.unresolved, []);
  const matches = extractOutcomes(source, 'matches');
  assert.deepEqual(matches.declared, ['true', 'false']);
  assert.equal(matches.confidence, 'exact');
});

test('extractOutcomes (rust): Result с внешней ошибкой остаётся явно неполным', () => {
  const r = extractOutcomes('pub fn run() -> Result<(), ExternalError> { todo!() }', 'run');
  assert.deepEqual(r.declared, ['Ok', 'Err']);
  assert.equal(r.confidence, 'shallow');
  assert.ok(r.unresolved.some((item) => item.includes('ExternalError')));
});

test('extractOutcomes (rust): Result с локальной struct ошибки имеет один полный Err', () => {
  const source = [
    'pub struct CodeMismatch;',
    'pub fn verify() -> Result<(), CodeMismatch> { Err(CodeMismatch) }',
  ].join('\n');
  const r = extractOutcomes(source, 'verify');
  assert.deepEqual(r.declared, ['Ok', 'Err']);
  assert.equal(r.confidence, 'syntactic');
  assert.deepEqual(r.unresolved, []);
});

test('extractOutcomes (rust): imported error разрешается workspace callback', () => {
  const source = 'pub fn run() -> Result<(), TrustError> { todo!() }';
  const r = extractOutcomes(source, 'run', {
    resolveType(name) {
      assert.equal(name, 'TrustError');
      return { kind: 'enum', variants: ['Revoked', 'Unavailable'] };
    },
  });
  assert.deepEqual(r.declared, ['Ok', 'Err::Revoked', 'Err::Unavailable']);
  assert.equal(r.confidence, 'workspace');
  assert.deepEqual(r.unresolved, []);
});

test('extractOutcomes (rust): символ не найден — null', () => {
  const source = 'pub fn foo() {}\n';
  assert.equal(extractOutcomes(source, 'Nope'), null);
});

test('extractOutcomes (rust) [C5]: panic! находится в КАЖДОМ вызове, а не через раз', () => {
  // ESCAPE_PATTERNS — регэкспы уровня модуля с флагом /g; без сброса lastIndex
  // между вызовами позиция сохраняется, и .test() чередует true/false на одном
  // и том же входе. Три последовательных вызова на одном источнике обязаны
  // дать одинаковый результат.
  const source = 'fn a() -> u8 { panic!(); 0 }\n';
  const r1 = extractOutcomes(source, 'a');
  const r2 = extractOutcomes(source, 'a');
  const r3 = extractOutcomes(source, 'a');
  assert.ok(r1.escaping.includes('panic!'), `call1 не нашёл panic!: ${JSON.stringify(r1.escaping)} (C5)`);
  assert.ok(r2.escaping.includes('panic!'), `call2 не нашёл panic! — lastIndex не сброшен между вызовами (C5)`);
  assert.ok(r3.escaping.includes('panic!'), `call3 не нашёл panic! (C5)`);
});

test('extractPublicTypes (rust): visibility внутри crate не является публичным API', () => {
  const source = [
    'pub struct PublicType;',
    'pub(crate) struct CrateType;',
    'pub(super) enum ParentType { A }',
    'pub(in crate::internal) struct ScopedType;',
  ].join('\n');
  assert.deepEqual(extractPublicTypes(source).map((item) => item.name), ['PublicType']);
});
