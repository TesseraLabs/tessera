#!/usr/bin/env bash
# usb-loop.sh — эмуляция съёмного носителя с удостоверением.
#
# Носитель — loop-устройство с файловой системой vfat, которому udev-правило
# проставляет ID_BUS=usb. Продукт при этом идёт своим штатным путём
# (udev-энумерация → монтирование → чтение p12): механизм обнаружения в самом
# продукте ради тестов не подменяется, иначе кейс перестал бы проверять то,
# что работает на живой машине.
#
#   usb-loop.sh attach <p12-path>   подключить носитель с этим удостоверением
#   usb-loop.sh detach              отключить и убрать за собой
#   usb-loop.sh swap <p12-path>     заменить удостоверение на подключённом носителе
#   usb-loop.sh status              напечатать текущее состояние
#
# Все команды идемпотентны: повторный attach просто перезаписывает удостоверение,
# detach на пустом месте завершается успехом. Это условие того, чтобы teardown
# мог выполняться на любом пути — включая прерывание кейса на середине.

set -euo pipefail

# При non-login ssh /sbin и /usr/sbin в PATH не попадают, а losetup, mkfs.vfat
# и udevadm живут именно там.
PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Состояние живёт в /run: это tmpfs, поэтому перезапуск контейнера или машины
# автоматически даёт чистое состояние без ручной уборки.
STATE_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}"
IMG="$STATE_DIR/usb.img"
LOOP_FILE="$STATE_DIR/usb.loop"
STAGE="$STATE_DIR/usb-stage"
RULES_FILE="/etc/udev/rules.d/99-tessera-fake-usb.rules"

# Размер образа: 16 МиБ — минимум, на котором mkfs.vfat уверенно делает FAT16
# и куда с запасом влезает связка p12 + CRL.
IMG_SIZE_MB="${TESSERA_E2E_IMG_SIZE_MB:-16}"

# Путь удостоверения внутри носителя. Дефолт совпадает с дефолтом продукта
# (pkcs12_path_pattern); кейсу с нестандартным шаблоном можно переопределить.
P12_DEST="${TESSERA_E2E_P12_DEST:-certs/user.p12}"

die() {
    echo "usb-loop: $*" >&2
    exit 1
}

require_root() {
    [ "$(id -u)" = "0" ] || die "требуются права root (losetup/mount/udevadm)"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "не найден инструмент: $1"
}

check_tools() {
    require_tool losetup
    require_tool mkfs.vfat
    require_tool mount
    require_tool umount
    require_tool udevadm
}

# Записывает udev-правило под конкретное имя устройства. Правило должно
# существовать до события add, иначе свойства не проставятся.
write_rule() {
    local kernel="$1"
    mkdir -p "$(dirname "$RULES_FILE")"
    cat > "$RULES_FILE" <<EOF
# Поддельный съёмный носитель e2e-контура: loop-устройство представляется
# продукту как USB-накопитель. Файл создаётся usb-loop.sh и им же удаляется.
SUBSYSTEM=="block", KERNEL=="$kernel", ENV{ID_BUS}="usb", ENV{ID_VENDOR_ID}="0951", ENV{ID_MODEL_ID}="1666", ENV{ID_SERIAL_SHORT}="E2ETEST", ENV{ID_FS_TYPE}="vfat"
EOF
    udevadm control --reload
}

remove_rule() {
    if [ -e "$RULES_FILE" ]; then
        rm -f "$RULES_FILE"
        udevadm control --reload || true
    fi
}

# Кладёт удостоверение на смонтированный носитель. Носитель монтируется на время
# записи и сразу отмонтируется: продукт должен смонтировать его сам, как на машине.
stage_p12() {
    local p12="$1" loopdev="$2" rc=0
    mkdir -p "$STAGE"
    mount "$loopdev" "$STAGE" || die "не удалось смонтировать $loopdev"
    # Копирование не под set -e: носитель нужно отмонтировать и при провале,
    # иначе следующий attach упрётся в занятый образ.
    {
        mkdir -p "$STAGE/$(dirname "$P12_DEST")" &&
        cp "$p12" "$STAGE/$P12_DEST" &&
        sync
    } || rc=1
    umount "$STAGE" || die "не удалось отмонтировать $STAGE"
    [ "$rc" -eq 0 ] || die "не удалось записать $P12_DEST на носитель"
}

current_loop() {
    [ -f "$LOOP_FILE" ] || return 1
    local dev
    dev="$(cat "$LOOP_FILE")"
    [ -n "$dev" ] && [ -b "$dev" ] || return 1
    # losetup мог освободить устройство помимо нас (например, после перезапуска
    # контейнера) — проверяем, что оно всё ещё указывает на наш образ.
    losetup "$dev" >/dev/null 2>&1 || return 1
    echo "$dev"
}

cmd_attach() {
    local p12="${1:-}"
    [ -n "$p12" ] || die "usage: usb-loop.sh attach <p12-path>"
    [ -f "$p12" ] || die "файл удостоверения не найден: $p12"
    require_root
    check_tools

    # Повторный attach не должен ломать состояние: если носитель уже подключён,
    # это просто замена удостоверения.
    local existing
    if existing="$(current_loop)"; then
        stage_p12 "$p12" "$existing"
        return 0
    fi

    # Прошлый запуск мог оборваться, оставив образ и правило без живого loop —
    # снимаем хвосты, прежде чем поднимать носитель заново.
    cmd_detach >/dev/null

    mkdir -p "$STATE_DIR"
    dd if=/dev/zero of="$IMG" bs=1M count="$IMG_SIZE_MB" status=none \
        || die "не удалось создать образ носителя"
    mkfs.vfat "$IMG" >/dev/null || die "mkfs.vfat не отработал на $IMG"

    # Имя устройства нужно знать до записи правила, поэтому свободное устройство
    # сначала выбирается, а привязывается уже после того, как правило на месте.
    local loopdev
    loopdev="$(losetup -f)" || die "нет свободного loop-устройства"
    write_rule "$(basename "$loopdev")"

    losetup "$loopdev" "$IMG" || die "не удалось привязать $loopdev к $IMG"
    echo "$loopdev" > "$LOOP_FILE"

    stage_p12 "$p12" "$loopdev"

    # Правило применяется к уже существующему устройству только повторным
    # событием add — без него ID_BUS останется непроставленным.
    udevadm trigger --action=add --subsystem-match=block
    udevadm settle --timeout=15 || die "udevadm settle не дождался обработки события"

    echo "$loopdev"
}

cmd_detach() {
    require_root
    check_tools

    local dev=""
    if [ -f "$LOOP_FILE" ]; then
        dev="$(cat "$LOOP_FILE")"
    fi

    # Носитель мог остаться смонтированным, если кейс прервался внутри stage_p12.
    if mountpoint -q "$STAGE" 2>/dev/null; then
        umount "$STAGE" || die "не удалось отмонтировать $STAGE"
    fi

    if [ -n "$dev" ] && [ -b "$dev" ]; then
        # Событие remove посылается по конкретному устройству и до отвязки:
        # так продукт узнаёт об извлечении носителя, а прочие блочные устройства
        # стенда лишних событий не получают.
        udevadm trigger --action=remove --name-match="$dev" 2>/dev/null || true
        udevadm settle --timeout=15 2>/dev/null || true
        losetup -d "$dev" 2>/dev/null || true
    fi
    # Образ мог остаться привязанным к другому устройству — снимаем все привязки
    # именно к нашему файлу, чтобы повторный attach не наткнулся на занятый образ.
    if [ -f "$IMG" ]; then
        local d
        for d in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
            losetup -d "$d" 2>/dev/null || true
        done
    fi

    rm -f "$LOOP_FILE" "$IMG"
    rmdir "$STAGE" 2>/dev/null || true
    remove_rule

    echo "detached"
}

cmd_swap() {
    local p12="${1:-}"
    [ -n "$p12" ] || die "usage: usb-loop.sh swap <p12-path>"
    [ -f "$p12" ] || die "файл удостоверения не найден: $p12"
    # Полный цикл detach → attach, а не подмена файла на месте: кейсам про
    # извлечение носителя нужны настоящие события remove и add.
    cmd_detach >/dev/null
    cmd_attach "$p12"
}

cmd_status() {
    local dev
    if dev="$(current_loop)"; then
        echo "attached: $dev"
        udevadm info --query=property --name="$dev" 2>/dev/null | grep -E '^ID_(BUS|FS_TYPE|SERIAL_SHORT)=' || true
    else
        echo "detached"
    fi
}

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        attach) cmd_attach "$@" ;;
        detach) cmd_detach "$@" ;;
        swap)   cmd_swap "$@" ;;
        status) cmd_status "$@" ;;
        ""|-h|--help)
            cat >&2 <<'EOF'
usage: usb-loop.sh <command> [args]
  attach <p12-path>   подключить эмулированный носитель с удостоверением
  detach              отключить носитель и убрать образ, правило и привязку
  swap <p12-path>     заменить удостоверение (полный цикл remove → add)
  status              показать состояние и udev-свойства носителя
EOF
            [ -z "$cmd" ] && exit 64 || exit 0
            ;;
        *) die "неизвестная команда: $cmd (attach|detach|swap|status)" ;;
    esac
}

main "$@"
