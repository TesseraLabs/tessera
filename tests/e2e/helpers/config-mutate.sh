#!/usr/bin/env bash
# config-mutate.sh — вносит в /etc/tessera/config.toml одну известную порчу.
#
# Кейсы конфигурации проверяют, что продукт отвергает неверную конфигурацию и
# называет причину. Каждая порча вносится ИМЕНОВАННОЙ операцией, а не строкой
# awk в YAML: во-первых, кейс читается как утверждение о продукте, во-вторых,
# место вставки имеет значение. Дописывание ключа в конец файла попадает уже
# после секций, TOML падает на разборе раньше семантической проверки, и кейс
# «поле вне диапазона» на деле проверял бы синтаксис.
#
# `restore` возвращает исходный файл и обязан вызываться в teardown. Он
# идемпотентен: без сохранённого эталона завершается успехом.

set -euo pipefail

CONFIG=/etc/tessera/config.toml
ORIGINAL=/var/lib/tessera/e2e-config.orig
# Живой конфиг не переписывается на месте: перенаправление усекает файл ДО того,
# как отработает awk, и упавший awk или прерванный прогон оставили бы на
# неодноразовой машине пустой /etc/tessera/config.toml — состояние, из которого
# стенд сам не выбирается. Новый текст собирается рядом и встаёт на место одним
# `mv`, поэтому конфиг в любой момент либо прежний, либо новый целиком.
STAGING="$CONFIG.e2e-new"
trap 'rm -f "$STAGING"' EXIT

# Режим и владелец снимаются с заменяемого файла: `mv` приносит атрибуты
# временного, созданного по umask, а конфиг с чужими правами продукт отвергнет,
# и это выглядело бы как поведение продукта, а не порча стенда.
commit_config() {
    chmod --reference="$CONFIG" "$STAGING"
    chown --reference="$CONFIG" "$STAGING"
    mv -f "$STAGING" "$CONFIG"
}

usage() {
    cat >&2 <<'EOF'
config-mutate.sh <операция>

  unknown-field        неизвестное поле верхнего уровня
  broken-toml          файл, не разбирающийся как TOML
  user-mapping         удалённая секция [[user_mapping]]
  roles-enforce        удалённый ключ [roles].enforce
  empty-anchors        пустой список trust.anchors
  no-revocation-mode   секция [trust.revocation] без ключа mode
  ocsp-without-url     mode = "ocsp" без ocsp_responder_url
  ocsp-key-unused      ocsp_responder_url при mode, где он не работает
  hook-path-unused     on_usb_removed_hook_path вне hook-режима
  hook-without-path    on_usb_removed = "hook" без пути
  partitions-100       max_usb_partitions вне диапазона
  deprecated-syslog    [logging].syslog_facility — устаревший ключ

  pinning-foreign      SPKI-pinning включён, в allow-list чужой отпечаток
  pinning-anchor       SPKI-pinning включён, в allow-list отпечаток своего якоря
  depth-1              max_chain_depth = 1 — короче фактической цепочки
  algorithms-substring whitelist алгоритмов из одной подстроки ("sha")
  no-intermediates     промежуточные не объявлены

  host-override-raw    идентичность узла из override, значение «грязное»
  host-override-clean  идентичность узла из override, значение уже нормализованное
  host-first-wins      первым источником — команда с чужим значением
  host-all-fail        единственный источник ничего не возвращает

  hook-session-open    хук стадии открытия сессии, создающий файл-отметку
  hook-relative-command хук с неабсолютным command[0]

  usb-allow-foreign    в списке разрешённых устройств — чужой VID:PID
  usb-allow-actual     в списке разрешённых устройств — VID:PID эмулятора

  restore              вернуть исходный конфиг
EOF
    exit 64
}

[ $# -eq 1 ] || usage

# Эталон снимается при первой порче: кейсы идут по одному, и каждый обязан
# начинать с той конфигурации, которую разложила подготовка suite.
save_original() {
    [ -f "$ORIGINAL" ] || cp "$CONFIG" "$ORIGINAL"
}

# Ключ верхнего уровня вставляется ПЕРЕД первой секцией — после неё он
# принадлежал бы секции и означал бы совсем другое.
insert_top_level() {
    save_original
    awk -v line="$1" '/^\[/ && !inserted { print line; inserted = 1 } { print }' \
        "$ORIGINAL" > "$STAGING"
    commit_config
}

# Ключ внутрь существующей секции.
insert_in_section() {
    save_original
    awk -v section="$1" -v line="$2" '{ print } $0 == section { print line }' \
        "$ORIGINAL" > "$STAGING"
    commit_config
}

# Замена значения ключа на месте: дубль ключа TOML не разрешает, а нам нужна
# именно проверка диапазона, а не разбора.
replace_key() {
    save_original
    awk -v key="$1" -v line="$2" '$0 ~ key { print line; next } { print }' \
        "$ORIGINAL" > "$STAGING"
    commit_config
}

# Замена секции [host_identity] целиком — от её заголовка до следующей секции.
replace_host_identity() {
    save_original
    awk -v body="$1" '
        /^\[host_identity\]/ { print; print body; skipping = 1; next }
        /^\[/               { skipping = 0 }
        skipping            { next }
        { print }
    ' "$ORIGINAL" > "$STAGING"
    commit_config
}

append_section() {
    save_original
    { cat "$ORIGINAL"; printf '\n%s\n' "$1"; } > "$STAGING"
    commit_config
}

case "$1" in
    unknown-field)      insert_top_level 'foo_bar = 1' ;;
    broken-toml)        save_original; printf 'это не toml [[[\n' > "$STAGING"
                        commit_config ;;
    user-mapping)       append_section '[[user_mapping]]
cert_cn = "engineer"
unix_user = "serv"' ;;
    roles-enforce)      insert_in_section '[roles]' 'enforce = false' ;;
    empty-anchors)      replace_key '^anchors = ' 'anchors = []' ;;
    no-revocation-mode) replace_key '^mode = "none"' '' ;;
    ocsp-without-url)   replace_key '^mode = "none"' 'mode = "ocsp"' ;;
    ocsp-key-unused)    insert_in_section '[trust.revocation]' \
                            'ocsp_responder_url = "http://127.0.0.1:8080"' ;;
    hook-path-unused)   append_section '[monitor]
on_usb_removed_hook_path = "/bin/true"' ;;
    hook-without-path)  append_section '[monitor]
on_usb_removed = "hook"' ;;
    partitions-100)     replace_key '^max_usb_partitions = ' 'max_usb_partitions = 100' ;;
    deprecated-syslog)  insert_in_section '[logging]' 'syslog_facility = "authpriv"' ;;

    pinning-foreign)
        save_original
        # Отпечаток заведомо чужой: 64 нуля — валидная форма, невозможное значение.
        awk '$0 ~ /^enabled = false/ { print "enabled = true"; next }
             $0 ~ /^allowed_root_spki_sha256 = / {
                 print "allowed_root_spki_sha256 = [\"" \
                     "0000000000000000000000000000000000000000000000000000000000000000\"]"
                 next
             }
             { print }' "$ORIGINAL" > "$STAGING"
        commit_config
        ;;
    pinning-anchor)
        save_original
        # Отпечаток берётся из самого якоря: кейс проверяет, что при
        # совпадении вход проходит, иначе «отказ при чужом» ничего не значил бы —
        # отказывать могло бы и просто включение pinning.
        spki="$(openssl x509 -in /etc/tessera/ca/bundle.pem -pubkey -noout \
            | openssl pkey -pubin -outform DER 2>/dev/null \
            | openssl dgst -sha256 -hex \
            | awk '{print $NF}')"
        awk -v spki="$spki" \
            '$0 ~ /^enabled = false/ { print "enabled = true"; next }
             $0 ~ /^allowed_root_spki_sha256 = / {
                 print "allowed_root_spki_sha256 = [\"" spki "\"]"; next
             }
             { print }' "$ORIGINAL" > "$STAGING"
        commit_config
        ;;
    depth-1)            replace_key '^max_chain_depth = ' 'max_chain_depth = 1' ;;
    algorithms-substring)
        replace_key '^allowed_signature_algorithms = ' 'allowed_signature_algorithms = ["sha"]'
        ;;
    no-intermediates)   replace_key '^intermediates = ' 'intermediates = []' ;;

    # Идентичность узла. Секция [host_identity] заменяется целиком: набор
    # ключей в ней зависит от выбранных источников, и правка по одному ключу
    # оставила бы в файле поля, запрещённые в новом сочетании.
    host-override-raw)   replace_host_identity 'sources = ["override"]
override = "AA:BB CC"' ;;
    host-override-clean) replace_host_identity 'sources = ["override"]
override = "aabbcc"' ;;
    host-first-wins)     replace_host_identity 'sources = ["custom_command", "machine_id"]
custom_command = "/usr/bin/hostname"' ;;
    host-all-fail)       replace_host_identity 'sources = ["custom_command"]
custom_command = "/usr/bin/true"
fallback = "deny"' ;;
    # Хуки. Отметка создаётся в /tmp: кейс наблюдает факт запуска хука, а не
    # его содержимое, и не трогает состояние продукта.
    hook-session-open)  append_section '[[hooks]]
stage = "session_open"
command = ["/usr/bin/touch", "/tmp/tessera-e2e-hook-ran"]
timeout_seconds = 5
on_failure = "warn"' ;;
    hook-relative-command) append_section '[[hooks]]
stage = "session_open"
command = ["touch", "/tmp/tessera-e2e-hook-ran"]
timeout_seconds = 5
on_failure = "warn"' ;;

    # Фильтр носителей по VID:PID. Эмулятор носителя объявляет 0951:1666 —
    # тот же формат, что печатает lsusb.
    usb-allow-foreign)  insert_top_level 'usb_allowed_devices = ["ffff:ffff"]' ;;
    usb-allow-actual)   insert_top_level 'usb_allowed_devices = ["0951:1666"]' ;;

    restore)
        # Идемпотентность: teardown выполняется и там, где порчи не было.
        if [ -f "$ORIGINAL" ]; then
            cp "$ORIGINAL" "$STAGING"
            commit_config
            rm -f "$ORIGINAL"
        fi
        ;;
    *) usage ;;
esac
