#!/usr/bin/env bash
# udevd-start.sh — поднятие systemd-udevd в профиле без менеджера служб.
#
# Astra-шный /sbin/init намеренно завершается без модуля ядра parsec
# («init: parsec module missing, terminating to prevent data leakage»), поэтому
# контейнер живёт без PID 1 = systemd. Обходить эту защиту незачем и нельзя:
# на настоящей Astra init работает штатно, а в контейнере нужен ровно один
# демон — udevd, без которого эмулированный носитель не получит своих свойств.
#
#   udevd-start.sh          поднять демон, если он ещё не запущен
#   udevd-start.sh status   показать состояние
#   udevd-start.sh stop     остановить (по pid из /proc, без масок по cmdline)
#
# Идемпотентно: повторный запуск ничего не ломает и завершается успехом.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Каталоги, где дистрибутивы держат бинарь демона; путь различается между
# Ubuntu 24.04 (/usr/lib/systemd) и Astra 1.8 (/lib/systemd).
UDEVD_CANDIDATES=(
    /lib/systemd/systemd-udevd
    /usr/lib/systemd/systemd-udevd
    /sbin/udevd
    /usr/sbin/udevd
)

die() {
    echo "udevd-start: $*" >&2
    exit 1
}

find_udevd() {
    local candidate
    for candidate in "${UDEVD_CANDIDATES[@]}"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# Процесс считается живым, только если он не зомби: PID 1 этого профиля —
# `sleep infinity`, он не пожинает осиротевших детей, и завершённый демон
# остаётся в таблице процессов.
process_alive() {
    local pid="$1" state
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "/proc/$pid/stat" ]; then
        state="$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1)"
        [ "$state" = "Z" ] && return 1
    fi
    return 0
}

# Ищет живой udevd среди процессов по имени исполняемого файла в /proc,
# а не по маске командной строки: маска совпала бы с самим этим скриптом.
running_pid() {
    local d comm pid
    for d in /proc/[0-9]*; do
        [ -r "$d/comm" ] || continue
        comm="$(cat "$d/comm" 2>/dev/null || true)"
        case "$comm" in
            systemd-udevd|udevd)
                pid="$(basename "$d")"
                process_alive "$pid" || continue
                echo "$pid"
                return 0
                ;;
        esac
    done
    return 1
}

cmd_start() {
    [ "$(id -u)" = "0" ] || die "требуются права root"

    local pid
    if pid="$(running_pid)"; then
        echo "already running: $pid"
        return 0
    fi

    local udevd
    udevd="$(find_udevd)" || die "systemd-udevd не найден (проверены: ${UDEVD_CANDIDATES[*]})"

    # Демону нужен собственный рабочий каталог в /run; в контейнере /run — tmpfs,
    # поэтому после перезапуска каталога не существует.
    mkdir -p /run/udev

    "$udevd" --daemon || die "не удалось запустить $udevd"

    # Готовность подтверждается тем, что демон отвечает на управляющие запросы:
    # факт форка сам по себе не значит, что сокет уже принимает события.
    local waited=0
    while [ "$waited" -lt 50 ]; do
        if udevadm control --ping >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
        waited=$((waited + 1))
    done

    if ! pid="$(running_pid)"; then
        die "udevd не поднялся"
    fi
    echo "started: $pid"
}

cmd_stop() {
    local pid
    if ! pid="$(running_pid)"; then
        echo "not running"
        return 0
    fi
    kill "$pid" 2>/dev/null || true
    local waited=0
    while process_alive "$pid" && [ "$waited" -lt 25 ]; do
        sleep 0.2
        waited=$((waited + 1))
    done
    echo "stopped: $pid"
}

cmd_status() {
    local pid
    if pid="$(running_pid)"; then
        echo "running: $pid"
    else
        echo "not running"
    fi
}

main() {
    case "${1:-start}" in
        start)  cmd_start ;;
        stop)   cmd_stop ;;
        status) cmd_status ;;
        -h|--help)
            cat >&2 <<'EOF'
usage: udevd-start.sh [start|stop|status]
  start (по умолчанию)  поднять systemd-udevd, если он не запущен
  stop                  остановить демон
  status                показать состояние
EOF
            exit 0
            ;;
        *) die "неизвестная команда: ${1} (start|stop|status)" ;;
    esac
}

main "$@"
