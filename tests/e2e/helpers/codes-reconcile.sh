#!/usr/bin/env bash
# codes-reconcile.sh — сверка записей выдачи с журналом устройства.
#
# Этот хелпер стоит на шве между двумя половинами телефонного канала: устройство
# пишет свои входы в хеш-цепочку (`[audit]`), выдающая сторона пишет запись на
# каждую выдачу — запрос инженера, грант и ступень кастодии, — и
# сверка `issuer codes reconcile` читает и то, и другое. Шов ломается тихо —
# читатель, разбирающий не тот формат, не падает, а находит ноль строк и
# объявляет отчёт полным. Поэтому проверяется он на настоящем журнале, который
# устройство написало само, а не на выгрузке, собранной стендом.
#
#   codes-reconcile.sh reconcile [--journal as-is|drop-middle|strip-logins|respell-engineer]
#                                [--server-chain as-is|empty|no-issuances|drop-middle|strip-custody|missing]
#                                [--declared-custody software|token]
#                                [--revoke-engineer-before-issuance]
#   codes-reconcile.sh cleanup
#
# Подготовку канала (артефакты, конфигурацию, PAM-сервис) делает
# `codes-server.sh prepare`, вход по коду — `codes-server.sh authenticate`. Этот
# хелпер их не дублирует: он читает то, что осталось после них, и запускает
# сверку.
#
# Мутации журнала — единственная логика здесь, и каждая отвечает своему вопросу:
#
#   as-is        журнал как есть; проверяется, что его формат вообще читается
#   drop-middle  изъята строка из середины; проверяется, что цепочка это ловит
#   respell-engineer  личный номер записан другим написанием того же номера
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
# Состояние, оставленное `codes-server.sh prepare`: номер устройства и каталог
# записей выдачи берутся оттуда, а не угадываются. Несовпадение номера с тем, что
# в записях, выглядело бы как «всё без пары» — то есть как отказ продукта.
PREPARED="$RUN_DIR/prepared.env"
# Цепочка выдач, какой её пишет выдающая сторона. На стенде её пишет тот же
# каталог записей: пока службы нет, цепочку кладёт туда хелпер выдачи.
SERVER_CHAIN="$RUN_DIR/server-chain.ndjson"
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
  reconcile [--journal as-is|drop-middle|strip-logins|respell-engineer]
            [--server-chain as-is|empty|drop-middle|strip-custody|missing]
            [--declared-custody software|token]
            [--revoke-engineer-before-issuance]
                        сверить цепочку выдач с журналом устройства
  expect-help-without-phone
                        проверить, что справка команды не поминает ни телефона,
                        ни квитанций
  cleanup               убрать рабочие копии (идемпотентно)
EOF
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "нужны права root: журнал устройства читается только им"
}

load_prepared() {
    [ -f "$PREPARED" ] || die \
        "подготовка канала не выполнялась: нет $PREPARED (нужен codes-server.sh prepare)"
    # shellcheck disable=SC1090  # файл создаёт codes-server.sh, состав известен из его шапки
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
        respell-engineer)
            # Тот же номер, набранный иначе: значение поля переводится в нижний
            # регистр. Разделители и регистр формат не считает, поэтому для
            # СВЕРКИ это тот же самый инженер, а для побайтового сравнения —
            # другой. Форма `\L` — GNU sed; целевые профили на нём и работают.
            sed -E 's/("claimed_engineer_no":")([^"]*)(")/\1\L\2\E\3/' "$source" > "$copy"
            if cmp -s "$source" "$copy"; then
                die "в журнале нет поля claimed_engineer_no или оно уже в нижнем регистре: кейс проверял бы совпадение файла с самим собой"
            fi
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

# Цепочка выдач: настоящая (после выдачи) или испорченная нужным образом.
#
# Пустая — это не «нет данных», а сценарий аудита: журнал устройства сверяется с
# цепочкой, в которой этих входов нет. Ровно так выглядит код, посчитанный в
# обход серверной процедуры.
#
# Порча идёт над копией: цепочка прогона нужна следующим шагам кейса целой.
stage_server_chain() {
    local kind="$1"
    local copy="$WORK_DIR/server-chain.ndjson"
    rm -f "$copy"
    case "$kind" in
        as-is)
            [ -s "$SERVER_CHAIN" ] || die "нет цепочки выдач $SERVER_CHAIN"
            cp "$SERVER_CHAIN" "$copy"
            ;;
        empty)
            : > "$copy"
            ;;
        drop-middle)
            [ -s "$SERVER_CHAIN" ] || die "нет цепочки выдач $SERVER_CHAIN"
            # Строка из СЕРЕДИНЫ: хвост цепочка не ловит, и вырезание хвоста
            # проверяло бы оговорку о незаверённом хвосте, а не сцепление.
            local total
            total="$(wc -l < "$SERVER_CHAIN" | tr -d " ")"
            [ "$total" -ge 3 ] || die \
                "в цепочке $total строк(и): изъять середину не из чего, кейсу нужна цепочка от трёх выдач"
            sed "2d" "$SERVER_CHAIN" > "$copy"
            ;;
        strip-custody)
            [ -s "$SERVER_CHAIN" ] || die "нет цепочки выдач $SERVER_CHAIN"
            # Поле ступени кастодии вырезается из записи внутри строки. Порча
            # ломает и сцепление, и разбор записи — кейс ждёт отказа, а не
            # умолчания, и любой из двух отказов его удовлетворяет.
            sed "s/;key_storage=[a-z]*//" "$SERVER_CHAIN" > "$copy"
            ;;
        no-issuances)
            # Журнал свежей выдающей стороны: строки есть, выдач нет. Файл
            # приезжает из комплекта стенда, а не собирается здесь: строки
            # цепочки пишет крейт продукта, и второй писатель формата разошёлся
            # бы с первым молча.
            local fixture="${FIXTURES_CODES_DIR:?в подготовке нет FIXTURES_CODES_DIR}/stand/server-chain-no-issuances.ndjson"
            [ -s "$fixture" ] || die \
                "нет фикстуры $fixture — её кладёт 'cargo xtask codes-stand-fixtures'"
            cp "$fixture" "$copy"
            ;;
        missing)
            printf "%s" "$WORK_DIR/server-chain-missing.ndjson"
            return 0
            ;;
        *)
            usage_error "неизвестное состояние цепочки выдач: $kind"
            ;;
    esac
    printf "%s" "$copy"
}

# Момент отзыва: на секунду раньше самой ранней выдачи в цепочке.
#
# Берётся из записи, а не из часов стенда: кейс проверяет отношение «выдача
# позже отзыва», и время машины к этому отношению не относится.
revocation_before_issuance() {
    local at
    at="$(record_field requested_at)"
    [ -n "$at" ] || die "в цепочке $SERVER_CHAIN не нашлось момента запроса"
    printf "%s" "$((at - 1))"
}

# Личный номер инженера из первой записи цепочки.
engineer_of_chain() {
    local id
    id="$(record_field engineer)"
    [ -n "$id" ] || die "в цепочке $SERVER_CHAIN не нашлось личного номера инженера"
    printf "%s" "$id"
}

# Поле первой записи цепочки, прочитанное ПРОДУКТОМ.
#
# Грант лежит в строке цепочки шестнадцатеричным полем, а запрос внутри гранта —
# снова шестнадцатеричным. Разбор sed'ом по такой строке не «иногда ошибается»,
# он не работает вовсе: искомого текста в ней нет. Читает `issuer codes record
# show` — единственный читатель формата.
record_field() {
    local name="$1"
    [ -s "$SERVER_CHAIN" ] || die "нет цепочки выдач $SERVER_CHAIN"
    command -v issuer >/dev/null 2>&1 || die "не найден issuer — разобрать запись выдачи нечем"
    install -d -m 0700 "$WORK_DIR"
    local first="$WORK_DIR/first-record.ndjson"
    head -1 "$SERVER_CHAIN" > "$first"
    issuer codes record show --record "$first" | sed -n "s/^$name=//p" | head -1
}

cmd_reconcile() {
    local mutation="as-is" chain="as-is" declared="" revoke=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --journal)
                [ "$#" -ge 2 ] || usage_error "--journal требует значения"
                mutation="$2"
                shift 2
                ;;
            --server-chain)
                [ "$#" -ge 2 ] || usage_error "--server-chain требует значения"
                chain="$2"
                shift 2
                ;;
            --declared-custody)
                [ "$#" -ge 2 ] || usage_error "--declared-custody требует значения"
                declared="$2"
                shift 2
                ;;
            --revoke-engineer-before-issuance)
                revoke=1
                shift
                ;;
            *) usage_error "неизвестный аргумент reconcile: $1" ;;
        esac
    done

    require_root
    load_prepared
    command -v issuer >/dev/null 2>&1 || die \
        "не найден issuer — сверку выполняет только 'issuer codes reconcile'"

    install -d -m 0700 "$WORK_DIR"
    local journal chain_file
    journal="$(stage_journal "$mutation")"
    chain_file="$(stage_server_chain "$chain")"

    # Необязательные части команды собираются заранее: ветка вокруг `exec`
    # означала бы две разные команды, а кейс проверяет одну.
    local extra=()
    [ -z "$declared" ] || extra+=(--declared-custody "$declared")
    if [ "$revoke" -eq 1 ]; then
        extra+=(--revoked "$(engineer_of_chain)=$(revocation_before_issuance)")
    fi

    # `exec`: код возврата и оба потока принадлежат продукту. Хелпер, который
    # пересказал бы их своими словами, стал бы вторым мнением о том, что
    # случилось.
    exec issuer codes reconcile \
        --server-chain "$chain_file" \
        --device-journal "$DEVICE_NUMBER=$journal" \
        "${extra[@]}"
}

# Справка команды: ни телефона, ни квитанций.
#
# Проверяется положительным утверждением о выводе, а не отсутствием строки в
# пустоте: `--help`, который вовсе не собрался, тоже «не содержит слова», и
# кейс на этом зеленел бы.
cmd_expect_help_without_phone() {
    command -v issuer >/dev/null 2>&1 || die "не найден issuer"
    local help
    help="$(issuer codes --help 2>&1)" || die "issuer codes --help не отработал"
    printf "%s" "$help" | grep -qi "reconcile" || die \
        "справка не похожа на справку канала: в ней нет даже команды сверки"
    local word
    for word in telephone receipt квитанц телефон; do
        if printf "%s" "$help" | grep -qi -- "$word"; then
            echo "codes-reconcile: справка всё ещё говорит про \`$word\`" >&2
            return 1
        fi
    done
    echo "справка не поминает ни телефона, ни квитанций"
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
        expect-help-without-phone) cmd_expect_help_without_phone ;;
        cleanup) cmd_cleanup ;;
        -h | --help)
            usage
            ;;
        *) usage_error "неизвестная команда: $command" ;;
    esac
}

main "$@"
