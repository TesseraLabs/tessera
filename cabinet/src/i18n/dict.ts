// The cabinet's RU/EN string table (D12: no i18n framework — a flat table of
// keys, one object per locale). `en` is authoritative for the key set; `ru`
// is type-checked against it (see `Dict` below), so a missing translation is
// a compile error, not a silent English fallback string shown to a Russian
// operator.

export const en = {
  app_title: "Tessera Issuer Cabinet",
  lang_switch_ru: "RU",
  lang_switch_en: "EN",

  // Parent certificate loading
  parent_file_label: "Parent certificate",
  parent_file_hint: "PEM or DER — the certificate that authorises this issuance",
  parent_kind_root: "Fleet root",
  parent_kind_root_desc: "Issues organisation CAs and assigns their envelopes.",
  parent_kind_org_ca: "Organisation CA",
  parent_kind_org_ca_desc: "Issues shift leaves within its delegation envelope.",
  parent_kind_leaf: "Leaf certificate",
  parent_kind_leaf_desc: "Not a CA — cannot issue anything.",
  parent_kind_unusable: "Not usable as an issuer",
  parent_subject: "Subject",
  parent_envelope_title: "Delegation envelope",
  parent_no_parent: "Load a parent certificate to see the available operations.",

  // Envelope fields
  envelope_require_tags: "Required tags",
  envelope_allow_roles: "Allowed roles",
  envelope_max_level: "Integrity level ceiling",
  envelope_max_ttl: "Session TTL ceiling (seconds)",

  // Key source
  key_source_label: "Leaf key source",
  key_source_spki: "Public key (SPKI file)",
  key_source_csr: "Certificate request (CSR file)",
  csr_file_label: "CSR file",
  csr_subject: "CSR subject",
  csr_signature_valid: "Self-signature",
  csr_signature_ok: "valid (proof of possession confirmed)",
  csr_signature_bad: "invalid — issuance unavailable",
  csr_prefill_marker: "requested in CSR",
  csr_rejected_roles: "requested in CSR, but out of scope — not applied",
  csr_rejected_integrity: "requested in CSR, but exceeds the ceiling — not applied",
  spki_file_label: "Public key (SPKI, DER)",

  // Common issuance fields
  field_subject: "Subject (RFC 4514)",
  field_not_before: "Valid from",
  field_not_after: "Valid until",
  field_algorithm: "Signature algorithm",
  field_host_binding: "Host binding",
  field_user_binding: "User binding",
  field_allowed_roles: "Allowed roles",
  field_max_integrity_level: "Integrity ceiling — level",
  field_max_integrity_categories: "Integrity ceiling — categories (hex bitmask)",
  field_profile_version: "Certificate profile version",
  field_add: "Add",
  field_remove: "Remove",

  // CA issuance fields
  ca_form_title: "Issue organisation CA",
  ca_field_require_tags: "Required tags (key=value)",
  ca_field_allow_roles: "Roles the CA may allow",
  ca_field_max_level: "Integrity level ceiling",
  ca_field_max_ttl: "Session TTL ceiling (seconds)",

  // Leaf issuance fields
  leaf_form_title: "Issue shift leaf",

  // Snapshot
  snapshot_file_label: "Inventory snapshot",
  snapshot_file_hint: "Signed export or a manually filled file",
  snapshot_none: "No snapshot loaded — fill fields manually",
  snapshot_origin_signed: "signed export",
  snapshot_origin_manual: "manual",
  snapshot_age: "Snapshot age",
  snapshot_verify_key_label: "Snapshot verification key (JWK, ECDSA P-256)",
  snapshot_verify_key_hint: "Paste the org's public verification key once per session",
  snapshot_rejected_bad_signature: "Snapshot signature is invalid — snapshot rejected",
  snapshot_rejected_no_key: "Snapshot is signed but no verification key is configured — snapshot rejected",

  // Agent
  agent_settings_title: "Signing agent",
  agent_address_label: "Agent address",
  agent_address_hint: "e.g. http://127.0.0.1:38217, printed by `issuer serve`",
  agent_token_label: "Session token",
  agent_token_hint: "printed by `issuer serve` at startup",
  agent_key_label: "CA key label",
  agent_key_hint: "must match the agent's --key flag exactly",
  agent_status_unknown: "not checked",
  agent_status_connecting: "connecting…",
  agent_status_connected: "connected",
  agent_status_disconnected: "not connected",
  agent_connect: "Connect",
  agent_save: "Save",

  // Summary / signing flow
  summary_title: "Operation summary",
  summary_confirm: "Confirm and sign",
  summary_cancel: "Cancel",
  sign_in_progress: "Signing…",
  sign_error: "Signing failed",
  issued_download: "Download certificate",
  issued_kind_shift_leaf: "Shift leaf",
  issued_kind_org_ca: "Organisation CA",
  issued_kind_crl: "CRL",

  // Journal
  journal_title: "Issuance journal",
  journal_load: "Load journal file",
  journal_download: "Download journal",
  journal_verify: "Verify chain",
  journal_status_intact: "intact, fully signed",
  journal_status_intact_unsigned_tail: "intact, unsigned tail from seq",
  journal_status_broken: "broken at position",
  journal_status_unknown: "unknown status",
  journal_entry_count: "entries",

  // Errors / dimensions
  error_generic: "Error",
  dimension_require_tags: "required tags",
  dimension_allow_roles: "allowed roles",
  dimension_max_level: "integrity level ceiling",
  dimension_max_ttl: "session TTL ceiling",

  // CRL
  crl_form_title: "Issue CRL",
  crl_field_this_update: "This update",
  crl_field_next_update: "Next update",
  crl_field_crl_number: "CRL number",
  crl_field_last_crl_number: "Last issued CRL number",
  crl_field_revoked: "Revoked certificates",
  crl_field_serial: "Serial (hex)",
  crl_field_revocation_date: "Revocation date",
  crl_field_reason: "Reason",
  crl_last_number_label: "Last issued CRL number for this CA",
  crl_candidates_label: "Issued by this CA (from the journal) — select to revoke",
  crl_candidates_none: "No issuances by this CA found in the loaded journal",
  crl_action_issue: "Build CRL summary",

  // Generic actions / statuses
  action_choose_file: "Choose file",
  action_build_summary: "Build summary",
  action_close: "Close",
  status_no_file: "No file selected",
  status_loading: "Loading…",
  section_operation: "Available operation",
  section_snapshot: "Inventory snapshot",
  section_agent: "Signing agent",
  section_journal: "Issuance journal",

  // Startup failure (fail-closed screen when the WASM core fails to initialise)
  startup_error_title: "The cabinet failed to start",
  startup_error_detail: "The issuance core could not be loaded. Technical detail",

  // Tabs
  tab_issue: "Issue",
  tab_journal: "Journal",

  // Help modals (design §3): a "?" button next to the parent and agent
  // section headings opens a local, CSP-safe modal with the same content as
  // docs/issuer.md's corresponding sections — no new claims, just surfaced
  // in-app.
  help_button_label: "Help",
  help_docs_more: "More detail",

  help_parent_title: "Parent certificate",
  help_parent_p1:
    "The cabinet's parent is either the fleet root (created by the PKI owner, outside day-to-day issuance) or an organisation CA (issued under the root with `issuer issue-ca`). Which one you load decides what the cabinet offers: a root issues organisation CAs and assigns their envelopes; an organisation CA issues shift leaves within its own envelope.",
  help_parent_p2:
    "The operator receives the parent file from the level above — it is not something the cabinet creates for you.",
  help_parent_p3: "Accepted formats: PEM or DER; the format is detected from the file's content.",

  help_agent_title: "The issuer serve agent",
  help_agent_p1:
    "issuer serve is a local HTTP bridge on 127.0.0.1 between the browser cabinet — which cannot reach a PKCS#11 token or HSM directly — and the signing key. It receives a built TBS from the cabinet and returns a signature; it never receives or stores a private key.",
  help_agent_p2: "Basic run, for the duration of a session:",
  help_agent_p3:
    "For a standing workstation, ready-made autostart examples ship in crates/tessera_issuer/examples/: systemd --user on Linux (issuer-serve.service), a launchd LaunchAgent on macOS (com.tesseralabs.issuer-serve.plist), and a logon-triggered Task Scheduler task on Windows (issuer-serve-task.xml).",
  help_agent_p4:
    "The agent prints a paired session token at startup (or writes it to a file with --daemon-token-file); the cabinet sends it back on every request in the X-Tessera-Session header.",
  help_agent_p5:
    "--allow-origin is required and repeatable: a request with no Origin header, or an Origin outside the allowlist, is rejected before the signing module is ever touched.",

  // Inventory constructor (design §1: build inventory in the cabinet instead
  // of loading a signed export file)
  snapshot_mode_manual: "Build",
  snapshot_mode_file: "Load file",
  snapshot_hosts_label: "Devices",
  snapshot_host_id_placeholder: "id (e.g. sha256:…)",
  snapshot_host_label_placeholder: "label (optional)",
  snapshot_users_label: "Users",
  snapshot_roles_label: "Roles",
  snapshot_tags_label: "Tags (key=value)",
  snapshot_build_action: "Build inventory",
  snapshot_download_action: "Download snapshot",

  // Leaf form: role list narrowed by the loaded inventory (spec issuer-cabinet)
  leaf_roles_narrowed_by_inventory: "Narrowed by the loaded inventory, relative to the parent's envelope.",
} as const;

export type DictKey = keyof typeof en;
export type Dict = Record<DictKey, string>;

export const ru: Dict = {
  app_title: "Кабинет выпуска Tessera",
  lang_switch_ru: "RU",
  lang_switch_en: "EN",

  parent_file_label: "Родительский сертификат",
  parent_file_hint: "PEM или DER — сертификат, из которого выводятся права на выпуск",
  parent_kind_root: "Корень парка",
  parent_kind_root_desc: "Выпускает CA организаций и назначает их рамки делегирования.",
  parent_kind_org_ca: "CA организации",
  parent_kind_org_ca_desc: "Выпускает листы смен строго в своих рамках делегирования.",
  parent_kind_leaf: "Лист",
  parent_kind_leaf_desc: "Не CA — не может ничего выпускать.",
  parent_kind_unusable: "Непригоден как эмитент",
  parent_subject: "Субъект",
  parent_envelope_title: "Рамки делегирования",
  parent_no_parent: "Загрузите родительский сертификат, чтобы увидеть доступные операции.",

  envelope_require_tags: "Обязательные метки",
  envelope_allow_roles: "Допустимые роли",
  envelope_max_level: "Потолок уровня целостности",
  envelope_max_ttl: "Потолок TTL сессии (сек.)",

  key_source_label: "Источник ключа листа",
  key_source_spki: "Публичный ключ (файл SPKI)",
  key_source_csr: "Запрос на сертификат (файл CSR)",
  csr_file_label: "Файл CSR",
  csr_subject: "Субъект CSR",
  csr_signature_valid: "Самоподпись",
  csr_signature_ok: "верна (proof of possession подтверждён)",
  csr_signature_bad: "неверна — выпуск недоступен",
  csr_prefill_marker: "запрошено в CSR",
  csr_rejected_roles: "запрошено в CSR, но вне рамок — не применено",
  csr_rejected_integrity: "запрошено в CSR, но выше потолка — не применено",
  spki_file_label: "Публичный ключ (SPKI, DER)",

  field_subject: "Субъект (RFC 4514)",
  field_not_before: "Действителен с",
  field_not_after: "Действителен до",
  field_algorithm: "Алгоритм подписи",
  field_host_binding: "Привязка к устройствам",
  field_user_binding: "Привязка к пользователям",
  field_allowed_roles: "Допустимые роли",
  field_max_integrity_level: "Потолок целостности — уровень",
  field_max_integrity_categories: "Потолок целостности — категории (hex-маска)",
  field_profile_version: "Версия профиля сертификата",
  field_add: "Добавить",
  field_remove: "Удалить",

  ca_form_title: "Выпуск CA организации",
  ca_field_require_tags: "Обязательные метки (ключ=значение)",
  ca_field_allow_roles: "Роли, которые CA может допускать",
  ca_field_max_level: "Потолок уровня целостности",
  ca_field_max_ttl: "Потолок TTL сессии (сек.)",

  leaf_form_title: "Выпуск листа смены",

  snapshot_file_label: "Снапшот инвентаря",
  snapshot_file_hint: "Подписанный экспорт или заполненный вручную файл",
  snapshot_none: "Снапшот не загружен — заполняйте поля вручную",
  snapshot_origin_signed: "подписанный экспорт",
  snapshot_origin_manual: "заполнен вручную",
  snapshot_age: "Возраст снапшота",
  snapshot_verify_key_label: "Ключ проверки снапшота (JWK, ECDSA P-256)",
  snapshot_verify_key_hint: "Вставьте публичный ключ проверки организации один раз за сессию",
  snapshot_rejected_bad_signature: "Подпись снапшота недействительна — снапшот отвергнут",
  snapshot_rejected_no_key: "Снапшот подписан, но ключ проверки не задан — снапшот отвергнут",

  agent_settings_title: "Агент подписи",
  agent_address_label: "Адрес агента",
  agent_address_hint: "например, http://127.0.0.1:38217 — печатается `issuer serve`",
  agent_token_label: "Токен сессии",
  agent_token_hint: "печатается `issuer serve` при старте",
  agent_key_label: "Метка ключа CA",
  agent_key_hint: "должна точно совпадать с флагом --key агента",
  agent_status_unknown: "не проверялся",
  agent_status_connecting: "подключение…",
  agent_status_connected: "подключён",
  agent_status_disconnected: "не подключён",
  agent_connect: "Подключить",
  agent_save: "Сохранить",

  summary_title: "Сводка операции",
  summary_confirm: "Подтвердить и подписать",
  summary_cancel: "Отменить",
  sign_in_progress: "Подписывается…",
  sign_error: "Ошибка подписи",
  issued_download: "Скачать сертификат",
  issued_kind_shift_leaf: "Лист смены",
  issued_kind_org_ca: "CA организации",
  issued_kind_crl: "CRL",

  journal_title: "Журнал выпусков",
  journal_load: "Загрузить файл журнала",
  journal_download: "Скачать журнал",
  journal_verify: "Проверить цепочку",
  journal_status_intact: "цела, полностью подписана",
  journal_status_intact_unsigned_tail: "цела, неподписанный хвост с seq",
  journal_status_broken: "нарушена в позиции",
  journal_status_unknown: "неизвестный статус",
  journal_entry_count: "записей",

  error_generic: "Ошибка",
  dimension_require_tags: "обязательные метки",
  dimension_allow_roles: "допустимые роли",
  dimension_max_level: "потолок уровня целостности",
  dimension_max_ttl: "потолок TTL сессии",

  crl_form_title: "Выпуск CRL",
  crl_field_this_update: "Дата выпуска (thisUpdate)",
  crl_field_next_update: "Следующее обновление (nextUpdate)",
  crl_field_crl_number: "Номер CRL",
  crl_field_last_crl_number: "Последний выпущенный номер CRL",
  crl_field_revoked: "Отозванные сертификаты",
  crl_field_serial: "Серийник (hex)",
  crl_field_revocation_date: "Дата отзыва",
  crl_field_reason: "Причина",
  crl_last_number_label: "Последний выпущенный номер CRL для этого CA",
  crl_candidates_label: "Выпущено этим CA (из журнала) — отметьте для отзыва",
  crl_candidates_none: "В загруженном журнале нет выпусков этого CA",
  crl_action_issue: "Сформировать сводку CRL",

  action_choose_file: "Выбрать файл",
  action_build_summary: "Сформировать сводку",
  action_close: "Закрыть",
  status_no_file: "Файл не выбран",
  status_loading: "Загрузка…",
  section_operation: "Доступная операция",
  section_snapshot: "Снапшот инвентаря",
  section_agent: "Агент подписи",
  section_journal: "Журнал выпусков",

  startup_error_title: "Кабинет не смог инициализироваться",
  startup_error_detail: "Не удалось загрузить ядро выпуска. Техническая информация",

  tab_issue: "Выпуск",
  tab_journal: "Журнал",

  help_button_label: "Справка",
  help_docs_more: "Подробнее",

  help_parent_title: "Родительский сертификат",
  help_parent_p1:
    "Родитель кабинета — либо корень парка (создаётся владельцем PKI, вне ежедневного выпуска), либо CA организации (выдаётся под корнем командой `issuer issue-ca`). От того, что загружено, зависит набор доступных операций: корень выпускает CA организаций и назначает их рамки делегирования; CA организации выпускает листы смен строго в своих рамках.",
  help_parent_p2:
    "Оператор получает файл родителя от уровня выше — кабинет его не создаёт.",
  help_parent_p3: "Принимаемые форматы: PEM или DER; формат определяется по содержимому файла.",

  help_agent_title: "Агент issuer serve",
  help_agent_p1:
    "issuer serve — локальный HTTP-мост на 127.0.0.1 между браузерным кабинетом (который не может обратиться к PKCS#11-токену или HSM напрямую) и ключом подписи. Он принимает от кабинета готовый TBS и возвращает подпись; приватный ключ через него не проходит.",
  help_agent_p2: "Базовый запуск на время сессии:",
  help_agent_p3:
    "Для постоянного рабочего места готовые примеры автостарта лежат в crates/tessera_issuer/examples/: systemd --user на Linux (issuer-serve.service), launchd LaunchAgent на macOS (com.tesseralabs.issuer-serve.plist), задача Task Scheduler с логон-триггером на Windows (issuer-serve-task.xml).",
  help_agent_p4:
    "Агент печатает парный токен сессии при старте (либо пишет в файл с --daemon-token-file); кабинет передаёт его в заголовке X-Tessera-Session с каждым запросом.",
  help_agent_p5:
    "--allow-origin обязателен и повторяем: запрос без заголовка Origin или с Origin вне allowlist отвергается до обращения к модулю подписи.",

  snapshot_mode_manual: "Собрать",
  snapshot_mode_file: "Загрузить файл",
  snapshot_hosts_label: "Устройства",
  snapshot_host_id_placeholder: "id (например, sha256:…)",
  snapshot_host_label_placeholder: "метка (необязательно)",
  snapshot_users_label: "Пользователи",
  snapshot_roles_label: "Роли",
  snapshot_tags_label: "Метки (ключ=значение)",
  snapshot_build_action: "Собрать инвентарь",
  snapshot_download_action: "Скачать снапшот",

  leaf_roles_narrowed_by_inventory: "Список сужен загруженным инвентарём относительно рамок родителя.",
};
