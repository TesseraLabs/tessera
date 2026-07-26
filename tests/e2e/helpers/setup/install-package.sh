#!/usr/bin/env bash
# install-package.sh — установка проверяемого пакета в окружение прогона.
#
# Действие подготовки suite: раннер выполняет его один раз за прогон как
# `helpers/setup/install-package.sh`.
#
# Проверяется артефакт штатного пайплайна, а не сборка изнутри прогона, поэтому
# пакет приезжает в окружение снаружи — раннер кладёт его по фиксированному пути
# до первого кейса. Скрипт пакет только ставит; отсутствие файла — сбой стенда,
# а не провал продукта, и отдаётся кодом 70.
#
# Идемпотентность: повторный запуск на уже установленной той же версии — успех.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH
export DEBIAN_FRONTEND=noninteractive

# Куда раннер кладёт пакет. Переопределяется на случай ручного прогона.
DEB_PATH="${TESSERA_E2E_DEB:-/opt/tessera-e2e/pkg/tessera.deb}"
PKG_NAME="${TESSERA_E2E_PKG_NAME:-tessera}"

# Коды, отличающие сбой стенда от вердикта продукта: раннер трактует их
# как ERROR по списку error_exit_codes профиля.
EXIT_INTERNAL=70

die_stand() {
    echo "install-package: $*" >&2
    exit "$EXIT_INTERNAL"
}

require_root() {
    [ "$(id -u)" = "0" ] || die_stand "требуются права root"
}

# Единственный кандидат в каталоге пакета — тоже валидный сценарий: раннер может
# положить файл под именем артефакта CI, а не под каноническим.
resolve_deb() {
    if [ -f "$DEB_PATH" ]; then
        echo "$DEB_PATH"
        return 0
    fi
    local dir found count
    dir="$(dirname "$DEB_PATH")"
    [ -d "$dir" ] || return 1
    count=0
    for found in "$dir"/*.deb; do
        [ -f "$found" ] || continue
        count=$((count + 1))
        DEB_PATH="$found"
    done
    [ "$count" -eq 1 ] || return 1
    echo "$DEB_PATH"
}

main() {
    require_root
    command -v dpkg >/dev/null 2>&1 || die_stand "не найден dpkg"

    local deb
    deb="$(resolve_deb)" || die_stand \
        "пакет не найден: ожидался $DEB_PATH. Пакет доставляет раннер до первого кейса; проверьте stand.toml → [package].deb"

    # Архитектура сверяется до установки: dpkg отказал бы и сам, но с текстом,
    # в котором проблему стенда легко принять за дефект пакета.
    local deb_arch host_arch
    deb_arch="$(dpkg-deb -f "$deb" Architecture 2>/dev/null || true)"
    host_arch="$(dpkg --print-architecture 2>/dev/null || true)"
    if [ -n "$deb_arch" ] && [ -n "$host_arch" ] \
        && [ "$deb_arch" != "$host_arch" ] && [ "$deb_arch" != "all" ]; then
        die_stand "архитектура пакета ($deb_arch) не совпадает с окружением ($host_arch)"
    fi

    local deb_version installed_version
    deb_version="$(dpkg-deb -f "$deb" Version 2>/dev/null || true)"
    installed_version="$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null || true)"

    if [ -n "$installed_version" ] && [ "$installed_version" = "$deb_version" ]; then
        # Та же версия уже стоит: подготовка выполняется один раз за прогон,
        # но окружение может быть переиспользовано между прогонами без --recreate.
        echo "already installed: $PKG_NAME $installed_version"
        return 0
    fi

    # Зависимости доустанавливаются, только если их не хватило: в контейнере без
    # сети apt-get всё равно ничего не сможет, и тогда честнее упасть на dpkg.
    if ! dpkg -i "$deb" >/tmp/install-package.log 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y -f >>/tmp/install-package.log 2>&1 || true
        fi
        if ! dpkg -i "$deb" >>/tmp/install-package.log 2>&1; then
            echo "install-package: установка не удалась, вывод dpkg:" >&2
            cat /tmp/install-package.log >&2 || true
            exit "$EXIT_INTERNAL"
        fi
    fi

    installed_version="$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null || true)"
    [ -n "$installed_version" ] || die_stand "после установки пакет $PKG_NAME не зарегистрирован в dpkg"

    echo "installed: $PKG_NAME $installed_version"
}

main "$@"
