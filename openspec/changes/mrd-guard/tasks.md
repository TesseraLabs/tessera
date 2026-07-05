# mrd-guard — tasks

## 1. Разведка на Astra VM (блокирует реализацию probe и RMW)

- [ ] 1.1 C-репродьюсер на Astra 1.8.4: способ детекта активного МРД
      (libpdp / sysfs / `astra-mac-control status`) — зафиксировать выбранный
      API в design.md (Open Questions → Decisions)
- [ ] 1.2 C-репродьюсер: чтение текущей метки процесса/файла/fd
      (`pdp_get_pid` / путь / fd) и подтверждение, что запись триплета с
      перенесённым полем 0 проходит под `PARSEC_CAP_CHMAC`

## 2. Открытый репозиторий (tessera)

- [x] 2.1 `startup_check`: enum `MrdState { Active, Inactive, Unknown }`,
      тип probe-функции, реальный probe за feature `astra-mac`
      (открытая сборка → `Unknown`)
- [x] 2.2 Новый чек `mac_mrd_active` в pipeline с матрицей
      required/auto/disabled × Active/Unknown/Inactive (ERROR/WARN/INFO
      по delta-спеке daemon-lifecycle)
- [x] 2.3 Unit-тесты матрицы (по образцу тестов `mac_runtime`), включая
      «required+Active → ERROR → демон не стартует»
- [x] 2.4 SPI-контракт в доках `tessera_core::mac` (backend НЕ ДОЛЖЕН (MUST NOT)
      изменять поле конфиденциальности) — только факты, без рыночных обоснований
- [x] 2.5 Абзац в `docs/mac-integrity.md`: граница МКЦ/МРД, статус
      «МРД-системы не поддерживаются», поведение чека
- [x] 2.6 `cargo test --workspace` + clippy зелёные; ревью
      master-code-reviewer пройдено (дымовой `tessera check` — см. 4.1)

## 3. Коммерческий backend (отдельный трек)

- [ ] 3.1 `tessera_mac_parsec::probe_mrd()` по результату 1.1
- [ ] 3.2 Кодек меток: обе оси триплета, decode возвращает поле 0;
      roundtrip-тесты с ненулевым полем 0
- [ ] 3.3 Read-modify-write поля 0 в `apply_session`,
      `set_file_label`, `set_fd_label`
- [ ] 3.4 Обновить закрытую полную спецификацию МКЦ-интеграции; ревью
      master-code-reviewer

## 4. Верификация на VM

- [ ] 4.1 E2E на Astra VM: обычная система — поведение меток не изменилось,
      `tessera check` дымово показывает `mac_mrd_active`
      (существующая техника VM-прогона)
- [ ] 4.2 E2E на VM с включённым МРД (если стенд достижим): логин присваивает
      уровень секретности → Tessera применяет `mac_mask` → поле 0 сохранено;
      `tessera check` показывает `mac_mrd_active` по матрице
