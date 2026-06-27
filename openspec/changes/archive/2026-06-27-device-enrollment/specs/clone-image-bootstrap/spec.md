# clone-image-bootstrap Delta Specification

## MODIFIED Requirements

### Requirement: CA-сторона (контракт)

CA-инструменты (настройка PKI, выпуск удостоверений, подготовка USB) НЕ ДОЛЖНЫ (MUST NOT) входить в `.deb` и в этот репозиторий — они не должны лежать на устройстве; поставляются отдельно. Контракт со стороны устройства: CA выпускает per-host
удостоверение по `hash_hex` из строки `active_under_current_config=yes` TSV-дампа `dump-host-id`.
Дополнительно (managed-enrollment): на том же USB-возврате CA-сторона ДОЛЖНА (MUST) отдавать
подписанный manifest с тегами устройства и первым bundle (роли+CRL, baseline `bundle_version`)
рядом с per-host удостоверением; теги и bundle не секретны и едут открыто. Назначение тегов
конкретному устройству — серверная сторона (Control inventory `hash_hex`→теги либо оператор при
установке), device их не выбирает.

#### Scenario: Выпуск per-host удостоверения
- **WHEN** CA-админ получает TSV-дамп от устройства после flip
- **THEN** per-host удостоверение выпускается по `hash_hex` активного источника и доставляется на устройство на USB-носителе (старые `.p12` удаляются)

#### Scenario: Доставка тегов и первого bundle на возврате
- **WHEN** CA-сторона готовит возвратный USB для managed-enrollment
- **THEN** рядом с per-host сертом кладётся подписанный manifest с тегами этого устройства и первым bundle (роли+CRL, baseline `bundle_version`)
