import test from 'node:test';
import assert from 'node:assert/strict';
import { extractOutcomes } from './csharp.mjs';

test('extractOutcomes (cs): enum — declared из членов, confidence exact', () => {
  const source = 'public enum Status : byte\n{\n    Revoked,\n    Valid = 1,\n}\n';
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['Revoked', 'Valid']);
  assert.equal(r.confidence, 'exact');
});

test('extractOutcomes (cs): иерархия result-типов — declared из прямых наследников', () => {
  const source = [
    'public abstract record CertStatus;',
    'public sealed record Revoked(DateTime When) : CertStatus;',
    'public sealed record Valid : CertStatus;',
  ].join('\n');
  const r = extractOutcomes(source, 'CertStatus');
  assert.deepEqual(r.declared, ['Revoked', 'Valid']);
  assert.equal(r.confidence, 'exact');
});

test('extractOutcomes (cs): OneOf<...>/Result<...> в типе возврата — declared из аргументов', () => {
  const source = [
    'public class Checker',
    '{',
    '    public Result<Success, NotFound> Check(string id)',
    '    {',
    '        if (id == null) throw new ArgumentNullException(nameof(id));',
    '        return Success.Instance;',
    '    }',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'Check');
  assert.deepEqual(r.declared, ['Success', 'NotFound']);
  assert.equal(r.confidence, 'syntactic');
  assert.deepEqual(r.escaping, ['throw new ArgumentNullException']);
});

test('extractOutcomes (cs): <exception cref> в XML-доке — declared, не escaping', () => {
  const source = [
    'public class Checker',
    '{',
    '    /// <summary>Проверяет удостоверение.</summary>',
    '    /// <exception cref="CertNotFoundException">сертификат не найден</exception>',
    '    public void Check(string id)',
    '    {',
    '        if (id == null) throw new CertNotFoundException(id);',
    '    }',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'Check');
  assert.deepEqual(r.declared, ['CertNotFoundException']);
  assert.deepEqual(r.escaping, [], 'документированное исключение не должно попадать в escaping');
  assert.equal(r.confidence, 'syntactic');
});

test('extractOutcomes (cs): необъявленный throw и throw; — escaping', () => {
  const source = [
    'public class Checker',
    '{',
    '    public void Check(string id)',
    '    {',
    '        try',
    '        {',
    '            DoWork(id);',
    '        }',
    '        catch (IOException)',
    '        {',
    '            throw;',
    '        }',
    '        ArgumentNullException.ThrowIfNull(id);',
    '        ObjectDisposedException.ThrowIf(disposed, this);',
    '    }',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'Check');
  assert.ok(r.escaping.includes('throw;'));
  assert.ok(r.escaping.includes('ArgumentNullException.ThrowIfNull('));
  assert.ok(r.escaping.includes('ObjectDisposedException.ThrowIf('));
});

test('extractOutcomes (cs): throw через динамическое создание — unresolved, не теряется', () => {
  const source = [
    'public class Checker',
    '{',
    '    public void Check(string kind)',
    '    {',
    '        var ex = (Exception)Activator.CreateInstance(errorTypes[kind]);',
    '        throw ex;',
    '    }',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'Check');
  assert.deepEqual(r.escaping, ['throw ex']);
  assert.ok(r.unresolved.some((u) => u.includes('Activator.CreateInstance')));
});

test('extractOutcomes (cs): void без документированных исключений — declared пуст, confidence shallow', () => {
  const source = [
    'public class Checker',
    '{',
    '    public void Ping()',
    '    {',
    '        Console.WriteLine("ping");',
    '    }',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'Ping');
  assert.deepEqual(r.declared, []);
  assert.equal(r.confidence, 'shallow');
});

test('extractOutcomes (cs): символ не найден — null', () => {
  const source = 'public class Foo {}\n';
  assert.equal(extractOutcomes(source, 'Nope'), null);
});
