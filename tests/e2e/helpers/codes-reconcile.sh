#!/usr/bin/env bash
# codes-reconcile.sh — сверка квитанций оператора с журналом устройства.
#
# Этот хелпер стоит на шве между двумя половинами телефонного канала: устройство
# пишет свои входы в хеш-цепочку (`[audit]`), оператор пишет квитанции выдачи, и
# сверка `issuer codes reconcile` читает и то, и другое. Шов ломается тихо —
# читатель, разбирающий не тот формат, не падает, а находит ноль строк и
# объявляет отчёт полным. Поэтому проверяется он на настоящем журнале, который
# устройство написало само, а не на выгрузке, собранной стендом.
#
#   codes-reconcile.sh reconcile [--journal as-is|drop-middle|strip-logins]
#                                [--receipts real|empty]
#   codes-reconcile.sh cleanup
#
# Подготовку канала (артефакты, конфигурацию, PAM-сервис) делает
# `codes-phone.sh prepare`, вход по коду — `codes-phone.sh authenticate`. Этот
# хелпер их не дублирует: он читает то, что осталось после них, и запускает
# сверку.
#
# Мутации журнала — единственная логика здесь, и каждая отвечает своему вопросу:
#
#   as-is        журнал как есть; проверяется, что его формат вообще читается
#   drop-middle  изъята строка из середины; проверяется, что цепочка это ловит
#   strip-logins остались только записи, не относящиеся ко входам; проверяется,
#                что журнал без входов — отказ, а не «полный и чистый» отчёт
#
# Мутации идут по КОПИИ. Журнал устройства — доказательство, и хелпер, который
# правит его на месте, уничтожает то, ради чего кейс написан.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Служебные коды, как у соседних хелперов: 64 — ошибка вызова, 70 — сбой стенда.
# Профили перечисляют их в error_exit_codes, поэтому кейс отличит сломанный
# стенд от отказа продукта. Код самой сверки хелпер НЕ подменяет: он её `exec`ает,
# и кейс видит ровно то, что вернул продукт.
EXIT_USAGE=64
EXIT_INTERNAL=70

CONFIG="${TESSERA_E2E_CONFIG:-/etc/tessera/config.toml}"
RUN_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}/codes"
# Состояние, оставленное `codes-phone.sh prepare`: номер устройства и каталог
# квитанций берутся оттуда, а не угадываются. Несовпадение номера с тем, что в
# квитанциях, выглядело бы как «всё без пары» — то есть как отказ продукта.
PREPARED="$RUN_DIR/prepared.env"
RECEIPTS_DIR="$RUN_DIR/receipts"
# Рабочие копии этого хелпера. В /run: перезапуск окружения обнуляет их сам.
WORK_DIR="$RUN_DIR/reconcile"

# Журнал устройства по умолчанию — тот же путь, что в `[audit].file`
# продукта. Конфигурация может его переопределить, поэтому сначала читается она.
DEFAULT_JOURNAL=/var/lib/tessera/audit.ndjson

die() {
    echo "codes-reconcile: $*" >&2
    exit "$EXIT_INTERNAL"
}

usage_error() {
    echo "codes-reconcile: $*" >&2
    usage
    exit "$EXIT_USAGE"
}

usage() {
    cat >&2 <<'EOF'
usage: codes-reconcile.sh <command> [args]
  reconcile [--journal as-is|drop-middle|strip-logins] [--receipts real|empty]
                        сверить квитанции оператора с журналом устройства
  cleanup               убрать рабочие копии (идемпотентно)
EOF
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "нужны права root: журнал устройства читается только им"
}

load_prepared() {
    [ -f "$PREPARED" ] || die \
        "подготовка канала не выполнялась: нет $PREPARED (нужен codes-phone.sh prepare)"
    # shellcheck disable=SC1090  # файл создаёт codes-phone.sh, состав известен из его шапки
    . "$PREPARED"
    [ -n "${DEVICE_NUMBER:-}" ] || die "в $PREPARED нет DEVICE_NUMBER"
}

# Путь журнала: из конфигурации, если она его называет, иначе умолчание продукта.
journal_path() {
    local configured=""
    if [ -f "$CONFIG" ]; then
        configured="$(sed -n '/^\[audit\]/,/^\[/ s/^[[:space:]]*file[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' \
            "$CONFIG" | head -1)"
    fi
    if [ -n "$configured" ]; then
        printf '%s' "$configured"
    else
        printf '%s' "$DEFAULT_JOURNAL"
    fi
}

# Готовит копию журнала под выбранную мутацию и печатает путь к ней.
stage_journal() {
    local mutation="$1" source
    source="$(journal_path)"
    [ -s "$source" ] || die \
        "журнал устройства $source пуст или отсутствует: вход по коду не выполнялся, \
либо устройство его не записало"

    install -d -m 0700 "$WORK_DIR"
    local copy="$WORK_DIR/device-$mutation.ndjson"
    case "$mutation" in
        as-is)
            cp "$source" "$copy"
            ;;
        drop-middle)
            # Изымается ПЕРВАЯ строка, а не последняя: обрезанный хвост цепочка
            # не ловит (префикс валидной цепочки валиден), и кейс, изымающий
            # хвост, проверял бы не то, что обещает.
            local lines
            lines="$(wc -l < "$source")"
            [ "$lines" -ge 2 ] || die \
                "в журнале $lines строк(а): изымать из середины нечего, стенд не в том состоянии"
            tail -n +2 "$source" > "$copy"
            ;;
        strip-logins)
            # Остаются строки, не относящиеся ко входам. Если таких нет вовсе —
            # пустой файл: журнал без единого входа это и есть проверяемый случай.
            grep -v '"op":"code_login"' "$source" > "$copy" || true
            ;;
        *)
            usage_error "неизвестная мутация журнала: $mutation"
            ;;
    esac
    printf '%s' "$copy"
}

# Каталог квитанций: настоящий (после выдачи) или заведомо пустой.
#
# Пустой — это не «нет данных», а сценарий аудита: журнал устройства сверяется с
# каталогом, в котором квитанций на эти входы нет. Ровно так выглядит код,
# выданный мимо записи.
stage_receipts() {
    local kind="$1"
    case "$kind" in
        real)
            [ -d "$RECEIPTS_DIR" ] || die "нет каталога квитанций $RECEIPTS_DIR"
            printf '%s' "$RECEIPTS_DIR"
            ;;
        empty)
            local empty="$WORK_DIR/receipts-empty"
            rm -rf "$empty"
            install -d -m 0700 "$empty"
            printf '%s' "$empty"
            ;;
        *)
            usage_error "неизвестный каталог квитанций: $kind"
            ;;
    esac
}

cmd_reconcile() {
    local mutation="as-is" receipts="real"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --journal)
                [ "$#" -ge 2 ] || usage_error "--journal требует значения"
                mutation="$2"
                shift 2
                ;;
            --receipts)
                [ "$#" -ge 2 ] || usage_error "--receipts требует значения"
                receipts="$2"
                shift 2
                ;;
            *) usage_error "неизвестный аргумент reconcile: $1" ;;
        esac
    done

    require_root
    load_prepared
    command -v issuer >/dev/null 2>&1 || die \
        "не найден issuer — сверку выполняет только 'issuer codes reconcile'"

    install -d -m 0700 "$WORK_DIR"
    local journal receipts_dir
    journal="$(stage_journal "$mutation")"
    receipts_dir="$(stage_receipts "$receipts")"

    # `exec`: код возврата и оба потока принадлежат продукту. Хелпер, который
    # пересказал бы их своими словами, стал бы вторым мнением о том, что
    # случилось.
    exec issuer codes reconcile \
        --receipts "$receipts_dir" \
        --device-journal "$DEVICE_NUMBER=$journal"
}

cmd_cleanup() {
    rm -rf "$WORK_DIR"
}

main() {
    [ "$#" -ge 1 ] || usage_error "не задана команда"
    local command="$1"
    shift
    case "$command" in
        reconcile) cmd_reconcile "$@" ;;
        cleanup) cmd_cleanup ;;
        -h | --help)
            usage
            ;;
        *) usage_error "неизвестная команда: $command" ;;
    esac
}

main "$@"
