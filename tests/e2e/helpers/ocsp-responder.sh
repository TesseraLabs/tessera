#!/usr/bin/env bash
# ocsp-responder.sh — локальный OCSP-респондер на `openssl ocsp` для кейсов отзыва.
#
#   ocsp-responder.sh start <ca-cert> <ca-key> <index> <port>
#   ocsp-responder.sh stop
#   ocsp-responder.sh status
#
# Останов выполняется ТОЛЬКО по pidfile. Убивать процесс по маске командной строки
# (`pkill -f "openssl ocsp"`) нельзя: маска совпадает с собственной командной строкой
# оболочки, из которой запущен teardown, и ssh-сессия убивает сама себя — прогон
# обрывается на ровном месте и выглядит как сбой стенда.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

STATE_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}"
PID_FILE="$STATE_DIR/ocsp.pid"
LOG_FILE="$STATE_DIR/ocsp.log"

die() {
    echo "ocsp-responder: $*" >&2
    exit 1
}

# Процесс считается живым, только если он не зомби. В контейнере без менеджера
# служб PID 1 — это `sleep infinity`, который не пожинает осиротевших детей:
# завершённый респондер остаётся зомби, и kill -0 на нём по-прежнему успешен.
# Без этой проверки остановка выглядела бы как неудачная.
process_alive() {
    local pid="$1" state
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "/proc/$pid/stat" ]; then
        # Третье поле /proc/<pid>/stat — состояние; имя процесса во втором поле
        # в скобках, поэтому режем всё до закрывающей скобки.
        state="$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1)"
        [ "$state" = "Z" ] && return 1
    fi
    return 0
}

# Возвращает pid живого респондера или пустую строку. Проверяется не только
# существование процесса, но и то, что это действительно наш openssl: pid мог быть
# переиспользован системой после аварийного завершения прошлого прогона.
running_pid() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    process_alive "$pid" || return 1
    if [ -r "/proc/$pid/cmdline" ]; then
        tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q 'ocsp' || return 1
    fi
    echo "$pid"
}

cmd_start() {
    local ca_cert="${1:-}" ca_key="${2:-}" index="${3:-}" port="${4:-}"
    [ -n "$ca_cert" ] && [ -n "$ca_key" ] && [ -n "$index" ] && [ -n "$port" ] \
        || die "usage: ocsp-responder.sh start <ca-cert> <ca-key> <index> <port>"
    [ -f "$ca_cert" ] || die "сертификат УЦ не найден: $ca_cert"
    [ -f "$ca_key" ] || die "ключ УЦ не найден: $ca_key"
    [ -f "$index" ] || die "index-файл не найден: $index"
    case "$port" in
        ''|*[!0-9]*) die "порт должен быть числом: $port" ;;
    esac
    command -v openssl >/dev/null 2>&1 || die "не найден openssl"

    # Повторный start не поднимает второй экземпляр: порт всё равно занят, а лишний
    # процесс остался бы без pidfile и пережил бы teardown.
    local pid
    if pid="$(running_pid)"; then
        echo "already running: $pid"
        return 0
    fi

    mkdir -p "$STATE_DIR"
    # Осиротевший pidfile от прошлого прогона мешает отличить «не запущен»
    # от «запущен и потерян».
    rm -f "$PID_FILE"

    # -nmin 0 / -ndays 1: ответ считается свежим сутки — кейсам про просроченный
    # ответ нужен отдельный респондер со своими параметрами, а не этот дефолт.
    openssl ocsp \
        -index "$index" \
        -CA "$ca_cert" \
        -rsigner "$ca_cert" \
        -rkey "$ca_key" \
        -port "$port" \
        -text \
        >"$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"

    # openssl ocsp падает не сразу (например, на занятом порту), поэтому старт
    # подтверждается тем, что процесс жив спустя короткую паузу.
    local waited=0
    while [ "$waited" -lt 20 ]; do
        if ! kill -0 "$new_pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "ocsp-responder: респондер не поднялся, вывод:" >&2
            cat "$LOG_FILE" >&2 || true
            exit 1
        fi
        # Респондер готов, как только слушает порт; при отсутствии ss/netstat
        # довольствуемся тем, что процесс жив.
        if ! command -v ss >/dev/null 2>&1; then
            break
        fi
        if ss -ltn 2>/dev/null | grep -q ":${port}[[:space:]]"; then
            break
        fi
        sleep 0.2
        waited=$((waited + 1))
    done

    echo "started: $new_pid port $port"
}

cmd_stop() {
    local pid
    if ! pid="$(running_pid)"; then
        # Идемпотентность: teardown вызывается и там, где респондер не поднимали.
        rm -f "$PID_FILE"
        echo "not running"
        return 0
    fi

    kill "$pid" 2>/dev/null || true
    local waited=0
    while process_alive "$pid" && [ "$waited" -lt 25 ]; do
        sleep 0.2
        waited=$((waited + 1))
    done
    if process_alive "$pid"; then
        kill -KILL "$pid" 2>/dev/null || true
        sleep 0.5
    fi
    if process_alive "$pid"; then
        die "не удалось остановить респондер (pid $pid)"
    fi

    rm -f "$PID_FILE"
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
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        start)  cmd_start "$@" ;;
        stop)   cmd_stop "$@" ;;
        status) cmd_status "$@" ;;
        ""|-h|--help)
            cat >&2 <<'EOF'
usage: ocsp-responder.sh <command> [args]
  start <ca-cert> <ca-key> <index> <port>   поднять респондер (pid в pidfile)
  stop                                      остановить строго по pidfile
  status                                    показать состояние
EOF
            [ -z "$cmd" ] && exit 64 || exit 0
            ;;
        *) die "неизвестная команда: $cmd (start|stop|status)" ;;
    esac
}

main "$@"
