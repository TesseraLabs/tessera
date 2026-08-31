// Тесты реестра владения ключами profile.yaml (C2, REVIEW.md).

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkProfileKeyOwnership, MANIFEST } from './profile-registry.mjs';

test('checkProfileKeyOwnership: ключ без владельца в манифесте — unregistered', () => {
  const profile = { kinds: { сущность: { anchors: { required: ['code'] } } }, wholly_unknown_key: 42 };
  const { unregistered } = checkProfileKeyOwnership(profile);
  assert.ok(unregistered.includes('wholly_unknown_key'), `неизвестный ключ не распознан как unregistered: ${JSON.stringify(unregistered)}`);
});

test('checkProfileKeyOwnership: человеческий title зарегистрирован как метаданные', () => {
  const profile = { kinds: { сущность: { title: 'Сущность' } } };
  const { unregistered, notImplemented } = checkProfileKeyOwnership(profile);
  assert.ok(!unregistered.includes('kinds.сущность.title'));
  assert.ok(!notImplemented.some((n) => n.path === 'kinds.*.title'));
});

test('checkProfileKeyOwnership: ключ, совпавший с implemented записью, не попадает ни в один список', () => {
  const profile = { kinds: { сущность: { anchors: { required: ['code'] } } } };
  const { unregistered, notImplemented } = checkProfileKeyOwnership(profile);
  assert.ok(!unregistered.includes('kinds.сущность.anchors.required'));
  assert.ok(!notImplemented.some((n) => n.path.includes('anchors.required')));
});

test('MANIFEST: каждый implemented-пункт имеет непустого owner', () => {
  for (const e of MANIFEST) {
    if (e.status !== 'implemented') continue;
    assert.ok(e.owner && e.owner.trim() !== '' && e.owner !== '—', `пункт манифеста "${e.pattern}" помечен implemented без owner`);
  }
});

test('MANIFEST: каждый not_implemented-пункт несёт причину', () => {
  for (const e of MANIFEST) {
    if (e.status !== 'not_implemented') continue;
    assert.ok(e.reason && e.reason.trim() !== '', `пункт манифеста "${e.pattern}" помечен not_implemented без причины`);
  }
});
