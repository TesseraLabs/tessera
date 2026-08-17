#!/usr/bin/env bash
# codes-enroll.sh — часть Codes в пакете первичной настройки, со стороны стенда.
#
# Хелпер исполняет роль стороны выдачи: собирает пакет первичной настройки —
# с частью Codes или без неё — и подаёт его `tessera enroll`. Проверяемое
# устройство при этом остаётся продуктом: ни один артефакт метода хелпер на место
# не кладёт (этим занят codes-phone.sh, и там это подготовка, а не проверка), он
# только формирует пакет и смотрит, что импорт с ним сделал.
#
#   codes-enroll.sh package <fixtures>/codes [--epoch N] [--without-codes]
#                              [--revoke-ticket]
#   codes-enroll.sh import
#   codes-enroll.sh import-expect-refused <регексп причины>
#   codes-enroll.sh note-counter
#   codes-enroll.sh assert-counter-reset
#   codes-enroll.sh assert-counter-kept
#   codes-enroll.sh cleanup
#
# Пакет собирается в режиме standalone: подписанный манифест потребовал бы ключа
# организации на стенде, а проверяемая здесь гарантия — про часть Codes в пакете,
# а не про подпись, которую стережёт suite device-enrollment.
#
# Импорт раскладывает не только Codes: standalone-пакет несёт ещё роли, теги и
# удостоверение узла. Поэтому `package` снимает копию затрагиваемых путей, а
# `cleanup` возвращает их — иначе suite оставил бы стенд с чужой ролевой базой,
# и следующий прогон проверял бы не то устройство.
#
# Все команды идемпотентны, `cleanup` выполняется и там, где `package` не
# отработал: teardown кейса зовёт его при любом исходе.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Служебные коды: 64 — ошибка вызова, 70 — сбой стенда. Профили перечисляют их в
# error_exit_codes, поэтому кейс отличит сломанный стенд от отказа продукта.
EXIT_USAGE=64
EXIT_INTERNAL=70

CODES_DIR="${TESSERA_E2E_CODES_DIR:-/var/lib/tessera/codes}"
STATE_DIR="$CODES_DIR/state"
COUNTER_FILE="$STATE_DIR/nonce.counter"

RUN_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}/codes-enroll"
PACKAGE_DIR="$RUN_DIR/package"
PIN_FILE="$RUN_DIR/container.pin"
NOTED_COUNTER="$RUN_DIR/noted.counter"

# Пути, которые импорт перезаписывает помимо Codes. Снимаются до импорта и
# возвращаются в cleanup.
BACKUP_DIR="$RUN_DIR/device-backup"
ROLES_DIR=/var/lib/tessera/roles
TAGS_FILE=/etc/tessera/device-tags.toml
HOST_P12=/var/lib/tessera/host.p12

die() {
    echo "codes-enroll: $*" >&2
    exit "$EXIT_INTERNAL"
}

usage_error() {
    echo "codes-enroll: $*" >&2
    usage
    exit "$EXIT_USAGE"
}

usage() {
    cat >&2 <<'EOF'
usage: codes-enroll.sh <command> [args]
  package <fixtures>/codes [--epoch N] [--without-codes] [--revoke-ticket]
                        собрать standalone-пакет первичной настройки; по
                        умолчанию — с частью Codes на эпохе из device.env
  import                подать собранный пакет `tessera enroll`; 0 только на
                        успешный импорт
  import-expect-refused <регексп>
                        импорт обязан отказать, и причина обязана совпасть с
                        регекспом; 0 только на такой отказ
  note-counter          запомнить текущее значение счётчика nonce
  assert-counter-reset  счётчик обнулён относительно запомненного
  assert-counter-kept   счётчик не обнулён относительно запомненного
  cleanup               вернуть окружение как было (идемпотентно)
EOF
}

require_root() {
    [ "$(id -u)" = "0" ] || die "требуются права root"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "не найден инструмент: $1"
}

# Манифест комплекта фикстур: номер устройства, эпоха, PIN контейнера доставки.
# Читается, а не угадывается: расхождение с материалом ключей выглядело бы как
# отказ продукта.
load_manifest() {
    local dir="$1"
    [ -f "$dir/device.env" ] || die "нет $dir/device.env — комплект фикстур не тот"
    # shellcheck disable=SC1090
    . "$dir/device.env"
    [ -n "${EPOCH:-}" ] || die "device.env не задаёт EPOCH"
    [ -n "${DEVICE_KEY_PIN:-}" ] || die "device.env не задаёт DEVICE_KEY_PIN"
    [ -n "${TICKET_NUMBER:-}" ] || die "device.env не задаёт TICKET_NUMBER"
}

sha256_of() {
    sha256sum "$1" | cut -d' ' -f1
}

# Копия путей, которые импорт перезапишет. Снимается один раз за прогон: второй
# `package` не должен затереть эталон уже импортированным состоянием.
backup_device_state() {
    [ -d "$BACKUP_DIR" ] && return 0
    mkdir -p "$BACKUP_DIR"
    [ -d "$ROLES_DIR" ] && cp -a "$ROLES_DIR" "$BACKUP_DIR/roles"
    [ -f "$TAGS_FILE" ] && cp -a "$TAGS_FILE" "$BACKUP_DIR/device-tags.toml"
    [ -f "$HOST_P12" ] && cp -a "$HOST_P12" "$BACKUP_DIR/host.p12"
    [ -d "$CODES_DIR" ] && cp -a "$CODES_DIR" "$BACKUP_DIR/codes"
    : >"$BACKUP_DIR/.taken"
}

restore_device_state() {
    [ -f "$BACKUP_DIR/.taken" ] || return 0
    rm -rf "$ROLES_DIR" "$CODES_DIR"
    [ -d "$BACKUP_DIR/roles" ] && cp -a "$BACKUP_DIR/roles" "$ROLES_DIR"
    [ -d "$BACKUP_DIR/codes" ] && cp -a "$BACKUP_DIR/codes" "$CODES_DIR"
    if [ -f "$BACKUP_DIR/device-tags.toml" ]; then
        cp -a "$BACKUP_DIR/device-tags.toml" "$TAGS_FILE"
    else
        rm -f "$TAGS_FILE"
    fi
    if [ -f "$BACKUP_DIR/host.p12" ]; then
        cp -a "$BACKUP_DIR/host.p12" "$HOST_P12"
    else
        rm -f "$HOST_P12"
    fi
    rm -rf "$BACKUP_DIR"
}

# ----------------------------------------------------------------------------
# package
# ----------------------------------------------------------------------------

cmd_package() {
    local fixtures="" epoch="" with_codes=1 revoke=0
    while [ $# -gt 0 ]; do
        case "$1" in
        --epoch)
            [ $# -ge 2 ] || usage_error "--epoch без значения"
            epoch="$2"
            shift 2
            ;;
        --without-codes)
            with_codes=0
            shift
            ;;
        --revoke-ticket)
            revoke=1
            shift
            ;;
        -*) usage_error "неизвестный ключ $1" ;;
        *)
            [ -z "$fixtures" ] || usage_error "лишний аргумент $1"
            fixtures="$1"
            shift
            ;;
        esac
    done
    [ -n "$fixtures" ] || usage_error "не задан каталог фикстур"
    require_root
    require_tool tessera
    require_tool sha256sum
    load_manifest "$fixtures"
    [ -n "$epoch" ] || epoch="$EPOCH"

    backup_device_state
    rm -rf "$PACKAGE_DIR"
    mkdir -p "$PACKAGE_DIR"

    # Общая часть пакета: удостоверение узла, теги, одна роль. Ровно то, что
    # везёт пакет парка «только Access».
    cp "$fixtures/device.p12" "$PACKAGE_DIR/host.p12"
    cat >"$PACKAGE_DIR/tags.toml" <<EOF
[tags]
region = "${REGION:-ru-central}"
EOF
    cat >"$PACKAGE_DIR/oper.toml" <<'EOF'
role = "oper"
version = 1
os = "linux"
name = "oper"
level = 1
EOF

    if [ "$with_codes" = "1" ]; then
        cp "$fixtures/device.p12" "$PACKAGE_DIR/codes-device.p12"
        cp "$fixtures/tickets.txt" "$PACKAGE_DIR/codes-tickets.txt"
        cp "$fixtures/ticket-authority.pem" "$PACKAGE_DIR/codes-ticket-authority.pem"
        {
            echo "epoch = $epoch"
            echo "key_container = { file = \"codes-device.p12\", sha256 = \"$(sha256_of "$PACKAGE_DIR/codes-device.p12")\" }"
            echo "tickets = { file = \"codes-tickets.txt\", sha256 = \"$(sha256_of "$PACKAGE_DIR/codes-tickets.txt")\" }"
            echo "ticket_authority = { file = \"codes-ticket-authority.pem\", sha256 = \"$(sha256_of "$PACKAGE_DIR/codes-ticket-authority.pem")\" }"
        } >"$PACKAGE_DIR/codes.toml"
        if [ "$revoke" = "1" ]; then
            # Отзыв билета едет тем же пакетом: список отзыва — такой же
            # артефакт части Codes, как билеты, и применяется до аутентификации.
            echo "$TICKET_NUMBER" >"$PACKAGE_DIR/codes-tickets.revoked"
            echo "ticket_revocations = { file = \"codes-tickets.revoked\", sha256 = \"$(sha256_of "$PACKAGE_DIR/codes-tickets.revoked")\" }" \
                >>"$PACKAGE_DIR/codes.toml"
        fi
        # PIN контейнера доставки приходит из фикстур и кладётся в файл: в argv
        # он попал бы в журнал процессов, а в реестре кейсов секретов быть не
        # должно вовсе.
        umask 077
        printf '%s' "$DEVICE_KEY_PIN" >"$PIN_FILE"
    else
        rm -f "$PIN_FILE"
    fi
}

# ----------------------------------------------------------------------------
# import
# ----------------------------------------------------------------------------

run_import() {
    local args=(enroll --standalone --import "$PACKAGE_DIR" --skip-check)
    [ -f "$PIN_FILE" ] && args+=(--codes-pin-file "$PIN_FILE")
    tessera "${args[@]}"
}

cmd_import() {
    require_root
    require_tool tessera
    [ -d "$PACKAGE_DIR" ] || die "пакет не собран — вызови package"
    run_import
}

cmd_import_expect_refused() {
    local pattern="${1:-}"
    [ -n "$pattern" ] || usage_error "не задан регексп причины отказа"
    require_root
    require_tool tessera
    [ -d "$PACKAGE_DIR" ] || die "пакет не собран — вызови package"

    local output status=0
    output="$(run_import 2>&1)" || status=$?
    if [ "$status" = "0" ]; then
        echo "импорт прошёл, а обязан был отказать" >&2
        echo "$output" >&2
        return 1
    fi
    if ! printf '%s' "$output" | grep -Eq "$pattern"; then
        echo "импорт отказал не по той причине: ждали /$pattern/" >&2
        echo "$output" >&2
        return 1
    fi
    echo "import refused as expected"
}

# ----------------------------------------------------------------------------
# счётчик nonce
# ----------------------------------------------------------------------------

read_counter() {
    [ -f "$COUNTER_FILE" ] || {
        echo 0
        return 0
    }
    tr -d '[:space:]' <"$COUNTER_FILE"
}

cmd_note_counter() {
    require_root
    mkdir -p "$RUN_DIR"
    read_counter >"$NOTED_COUNTER"
    echo "counter noted: $(cat "$NOTED_COUNTER")"
}

noted_counter() {
    [ -f "$NOTED_COUNTER" ] || die "счётчик не запомнен — вызови note-counter"
    cat "$NOTED_COUNTER"
}

cmd_assert_counter_reset() {
    require_root
    local before after
    before="$(noted_counter)"
    after="$(read_counter)"
    [ "$before" -gt 0 ] || die "запомненный счётчик нулевой — кейс ничего не проверяет"
    if [ "$after" -ge "$before" ]; then
        echo "счётчик не обнулён: было $before, стало $after" >&2
        return 1
    fi
    echo "counter reset: $before -> $after"
}

cmd_assert_counter_kept() {
    require_root
    local before after
    before="$(noted_counter)"
    after="$(read_counter)"
    [ "$before" -gt 0 ] || die "запомненный счётчик нулевой — кейс ничего не проверяет"
    if [ "$after" -lt "$before" ]; then
        echo "счётчик откатился: было $before, стало $after" >&2
        return 1
    fi
    echo "counter kept: $before -> $after"
}

# ----------------------------------------------------------------------------
# cleanup
# ----------------------------------------------------------------------------

cmd_cleanup() {
    [ "$(id -u)" = "0" ] || return 0
    restore_device_state
    rm -rf "$RUN_DIR"
}

# ----------------------------------------------------------------------------

main() {
    [ $# -ge 1 ] || usage_error "не задана команда"
    local command="$1"
    shift
    case "$command" in
    package) cmd_package "$@" ;;
    import) cmd_import "$@" ;;
    import-expect-refused) cmd_import_expect_refused "$@" ;;
    note-counter) cmd_note_counter "$@" ;;
    assert-counter-reset) cmd_assert_counter_reset "$@" ;;
    assert-counter-kept) cmd_assert_counter_kept "$@" ;;
    cleanup) cmd_cleanup "$@" ;;
    *) usage_error "неизвестная команда $command" ;;
    esac
}

main "$@"
