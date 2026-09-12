#!/usr/bin/env bash
# codes-overlay.sh — показ challenge оверлеем в графическом входе.
#
#   codes-overlay.sh expect-overlay-login <user> [--level N]
#   codes-overlay.sh cleanup
#
# Разговор ведёт helpers/codes-server.sh: артефакты, выдача и код — его работа, и
# второй реализации здесь нет. Этот хелпер наблюдает ЭКРАН: пока попытка жива, на
# дисплее греетера обязан висеть символ, который читается сторонним декодером, а
# после принятого кода — не обязан.
#
# Символ ищется не по окну, а по снимку экрана. Окно оверлея имени не несёт
# (override-redirect, WM_NAME не ставится), и проверка «есть окно такого размера»
# зеленела бы на пустом окне; прочитанный с экрана challenge — наблюдение того
# самого, ради чего оверлей существует.
#
# ЧЕГО ЭТОТ КЕЙС НЕ ПРОВЕРЯЕТ. Код подаётся драйвером PAM, а не полем греетера:
# набрать его в чужой форме стенд не умеет. Режим 2a дизайна (2026-07-03, §4.1)
# закрыт здесь наполовину — показ оверлеем проверен, приём кода родным полем
# греетера нет. Записано в BASELINE.md.
#
# Требует живого графического сеанса: контейнерный профиль дисплея не даёт.

set -euo pipefail

EXIT_USAGE=64
EXIT_INTERNAL=70

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CODES_SERVER="$HELPERS_DIR/codes-server.sh"

RUN_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}/codes-overlay"

# Дисплей и права на него — те же, что у греетера. Угадывать их нельзя: оверлей
# получает их от модуля, и именно эта передача ломается первой на новом парке.
OVERLAY_DISPLAY="${TESSERA_E2E_DISPLAY:-:0}"
OVERLAY_XAUTHORITY="${TESSERA_E2E_XAUTHORITY:-}"

# Имя процесса оверлея. Совпадает с бинарём пакета; расхождение выглядит как
# «оверлей не поднялся» и разбирается по журналу модуля.
OVERLAY_PROCESS="${TESSERA_E2E_OVERLAY_PROCESS:-tessera-qr-overlay}"

die() {
    echo "codes-overlay: $*" >&2
    exit "$EXIT_INTERNAL"
}

usage() {
    cat >&2 <<'USAGE'
usage: codes-overlay.sh <command> [args]
  expect-overlay-login <user> [--level N]
                        вход по коду в графическом сеансе: символ обязан
                        появиться на экране, прочитаться декодером и исчезнуть
                        после принятого кода
  expect-overlay-from-pam-items <user> [--level N]
                        то же, но дисплей и права на него модуль получает
                        только items PAM_XDISPLAY/PAM_XAUTHDATA, а переменных
                        DISPLAY и XAUTHORITY в окружении разговора нет — так
                        устроен штатный греетер fly-dm
  cleanup               убрать состояние прогона (идемпотентно)
USAGE
}

usage_error() {
    echo "codes-overlay: $*" >&2
    usage
    exit "$EXIT_USAGE"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "не найден инструмент: $1"
}

# Снимает корневое окно и отдаёт прочитанное декодером. Пустой вывод — на экране
# читаемого символа нет; это законный исход, а не сбой.
decode_screen() {
    local shot="$RUN_DIR/screen.png"
    DISPLAY="$OVERLAY_DISPLAY" XAUTHORITY="$XAUTH" import -silent -window root "$shot" \
        2>/dev/null || return 0
    zbarimg --quiet --raw "$shot" 2>/dev/null || true
}

overlay_running() {
    pgrep -x "$OVERLAY_PROCESS" >/dev/null 2>&1
}

cmd_expect_overlay_login() {
    local user="${1:-}" level=0
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент expect-overlay-login: $1" ;;
        esac
    done
    [ -n "$user" ] || usage_error "usage: codes-overlay.sh expect-overlay-login <user> [--level N]"

    [ "$(id -u)" = "0" ] || die "требуются права root"
    require_tool import
    require_tool zbarimg
    require_tool pgrep
    [ -x "$CODES_SERVER" ] || die "нет $CODES_SERVER — разговор вести нечем"

    XAUTH="$OVERLAY_XAUTHORITY"
    if [ -z "$XAUTH" ]; then
        die "не задан TESSERA_E2E_XAUTHORITY: без прав на дисплей греетера снимок экрана невозможен, а угаданный путь дал бы «оверлея нет» вместо ответа"
    fi
    [ -r "$XAUTH" ] || die "нет доступа к $XAUTH"

    install -d -m 0700 "$RUN_DIR"
    local log="$RUN_DIR/conversation.log"

    # Разговор идёт в фоне: символ живёт только между показом challenge и
    # принятым кодом, и наблюдать его после завершения входа уже не по чему.
    #
    # Дисплей передаётся ОКРУЖЕНИЕМ — это запасной путь модуля, тот самый, что
    # работает под sshd и pam-drive. Путь дисплей-менеджера проверяет соседняя
    # команда.
    DISPLAY="$OVERLAY_DISPLAY" XAUTHORITY="$XAUTH" \
        "$CODES_SERVER" authenticate "$user" --level "$level" > "$log" 2>&1 &
    watch_conversation $! "$log"
}

# Тот же вход, но дисплей модуль узнаёт ТОЛЬКО из items PAM.
#
# Разница с командой выше — единственная и она же вся суть: у процесса fly-dm
# нет ни DISPLAY, ни XAUTHORITY, дисплей он называет модулю items PAM_XDISPLAY и
# PAM_XAUTHDATA. Кейс, ведущий разговор с этими переменными в окружении, зеленел
# бы на запасном пути и ничего не говорил бы о графическом входе.
#
# Куки берётся из того же файла xauth греетера, каким снимается экран: своей
# куки стенд не заводит, иначе проверялся бы доступ к дисплею, выданный стендом.
cmd_expect_overlay_from_pam_items() {
    local user="${1:-}" level=0
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент expect-overlay-from-pam-items: $1" ;;
        esac
    done
    [ -n "$user" ] || usage_error "usage: codes-overlay.sh expect-overlay-from-pam-items <user> [--level N]"

    [ "$(id -u)" = "0" ] || die "требуются права root"
    require_tool import
    require_tool zbarimg
    require_tool pgrep
    require_tool xauth
    [ -x "$CODES_SERVER" ] || die "нет $CODES_SERVER — разговор вести нечем"

    XAUTH="$OVERLAY_XAUTHORITY"
    if [ -z "$XAUTH" ]; then
        die "не задан TESSERA_E2E_XAUTHORITY: без прав на дисплей греетера снимок экрана невозможен, а угаданный путь дал бы «оверлея нет» вместо ответа"
    fi
    [ -r "$XAUTH" ] || die "нет доступа к $XAUTH"

    # Последние два поля строки xauth — имя схемы и шестнадцатеричная куки.
    # Строка выбирается по дисплею: в файле греетера их бывает несколько.
    local entry scheme cookie
    entry="$(xauth -f "$XAUTH" list "$OVERLAY_DISPLAY" 2>/dev/null | head -n 1)"
    [ -n "$entry" ] || die "в $XAUTH нет записи для дисплея $OVERLAY_DISPLAY"
    scheme="$(printf '%s' "$entry" | awk '{print $(NF-1)}')"
    cookie="$(printf '%s' "$entry" | awk '{print $NF}')"
    [ -n "$scheme" ] && [ -n "$cookie" ] || die "запись xauth разобрана не полностью: $entry"

    install -d -m 0700 "$RUN_DIR"
    local log="$RUN_DIR/conversation.log"

    TESSERA_E2E_PAM_XDISPLAY="$OVERLAY_DISPLAY" \
    TESSERA_E2E_PAM_XAUTHDATA="$scheme:$cookie" \
        "$CODES_SERVER" authenticate-as-greeter "$user" --level "$level" > "$log" 2>&1 &
    watch_conversation $! "$log"
}

# Наблюдает экран, пока идёт разговор, и выносит вердикт по увиденному.
#
# $1 — pid разговора, $2 — его журнал. Вынесено в общую функцию не ради краткости:
# две команды обязаны судить об одном и том же по одним и тем же признакам, иначе
# сравнивать их исходы нельзя.
watch_conversation() {
    local conversation="$1" log="$2"

    local decoded="" saw_process=0 waited=0
    local limit="${TESSERA_E2E_OVERLAY_TIMEOUT:-120}"
    while kill -0 "$conversation" 2>/dev/null; do
        overlay_running && saw_process=1
        if [ -z "$decoded" ]; then
            decoded="$(decode_screen)"
        fi
        sleep 0.5
        waited=$((waited + 1))
        if [ "$waited" -ge $((limit * 2)) ]; then
            kill "$conversation" 2>/dev/null || true
            die "разговор не кончился за ${limit} с (см. $log)"
        fi
    done

    local rc=0
    wait "$conversation" || rc=$?
    cat "$log"

    if [ "$rc" -ne 0 ] || ! grep -qF 'auth: PAM_SUCCESS (0)' "$log"; then
        echo "codes-overlay: вход не прошёл (код $rc), см. $log" >&2
        return 1
    fi

    if [ "$saw_process" -eq 0 ]; then
        echo "codes-overlay: процесс $OVERLAY_PROCESS не поднимался за весь вход" >&2
        return 1
    fi

    case "$decoded" in
        "") echo "codes-overlay: на экране не было читаемого символа за весь вход" >&2; return 1 ;;
        *"tessera-codes/v1/signed-challenge;"*) ;;
        *)
            echo "codes-overlay: с экрана прочитан не challenge: $decoded" >&2
            return 1
            ;;
    esac

    # Оверлей обязан уйти вместе с попыткой: оставшийся символ на экране входа —
    # это показанный посторонним challenge, годный до конца своего окна.
    if overlay_running; then
        echo "codes-overlay: после принятого кода процесс $OVERLAY_PROCESS ещё жив" >&2
        return 1
    fi
    if [ -n "$(decode_screen)" ]; then
        echo "codes-overlay: после принятого кода символ остался на экране" >&2
        return 1
    fi

    echo "overlay: shown, code accepted, overlay closed"
}

# Идемпотентен и не опирается на expect-overlay-login: teardown кейса выполняется
# при любом исходе.
cmd_cleanup() {
    [ "$(id -u)" = "0" ] || die "требуются права root"
    pkill -x "$OVERLAY_PROCESS" 2>/dev/null || true
    rm -rf "$RUN_DIR"
    echo "cleaned"
}

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        expect-overlay-login) cmd_expect_overlay_login "$@" ;;
        expect-overlay-from-pam-items) cmd_expect_overlay_from_pam_items "$@" ;;
        cleanup)              cmd_cleanup "$@" ;;
        -h|--help)            usage; exit 0 ;;
        "")                   usage; exit "$EXIT_USAGE" ;;
        *)                    usage_error "неизвестная команда: $cmd" ;;
    esac
}

main "$@"
