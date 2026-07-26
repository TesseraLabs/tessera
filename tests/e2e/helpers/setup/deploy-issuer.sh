#!/usr/bin/env bash
# deploy-issuer.sh — подготовка окружения к кейсам выпуска удостоверений.
#
# Действие подготовки suite: раннер выполняет его один раз за прогон как
# `helpers/setup/deploy-issuer.sh`.
#
# Сам `issuer` в окружение не собирается и не ставится: проверяется артефакт
# штатного пайплайна, и раннер кладёт бинарь по фиксированному пути до первого
# кейса — ровно как .deb для install-package.sh. Скрипт проверяет, что доставка
# состоялась и бинарь в этом окружении вообще запускается, что на месте openssl
# (кейсы генерируют им ключи и собирают PKCS#12), и готовит рабочий каталог
# выпуска. Всё это — свойства стенда: их нарушение отдаётся кодом 70, чтобы
# раннер назвал прогон ERROR, а не приписал продукту провал.
#
# Идемпотентность: повторный запуск на готовом окружении — успех.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Куда раннер кладёт бинарь. Переопределяется на случай ручного прогона.
ISSUER_PATH="${TESSERA_E2E_ISSUER:-/usr/local/bin/issuer}"

# Рабочий каталог кейсов выпуска. Кейсы пересоздают его сами первым шагом,
# но подготовка обязана оставить окружение в известном состоянии: остатки
# чужого прогона здесь — это приватные ключи, а не безобидный мусор.
WORK_DIR="${TESSERA_E2E_ISSUER_WORK:-/tmp/issuer-e2e}"

EXIT_INTERNAL=70

die_stand() {
    echo "deploy-issuer: $*" >&2
    exit "$EXIT_INTERNAL"
}

require_root() {
    [ "$(id -u)" = "0" ] || die_stand "требуются права root"
}

check_issuer() {
    [ -f "$ISSUER_PATH" ] || die_stand \
        "бинарь выпуска не найден: ожидался $ISSUER_PATH. Бинарь доставляет раннер до первого кейса"
    [ -x "$ISSUER_PATH" ] || die_stand "бинарь $ISSUER_PATH не исполняемый"

    # Кейсы зовут `issuer` без пути, поэтому мало доставки — он должен
    # находиться через PATH оболочки шага.
    local resolved
    resolved="$(command -v issuer 2>/dev/null || true)"
    [ -n "$resolved" ] || die_stand \
        "issuer не находится через PATH ($PATH); кейсы вызывают его без пути"

    # Запуск, а не только наличие файла: собранный не под это окружение бинарь
    # существует и не работает, и без проверки это выглядело бы дефектом выпуска.
    local version
    version="$("$ISSUER_PATH" --version 2>&1)" \
        || die_stand "бинарь $ISSUER_PATH не запускается: $version"

    ISSUER_VERSION="$version"
}

check_openssl() {
    command -v openssl >/dev/null 2>&1 || die_stand \
        "не найден openssl: кейсы выпуска генерируют им ключи и собирают PKCS#12"

    # Проверяются ровно те операции, на которых стоят кейсы. Наличие бинаря их
    # не гарантирует: сборка openssl без нужного провайдера — обычное дело на
    # сертифицированных дистрибутивах, и упавший на этом кейс выглядел бы
    # отказом выпуска.
    local probe
    probe="$(mktemp -d)" || die_stand "не создать временный каталог для проверки openssl"
    chmod 0700 "$probe"
    # shellcheck disable=SC2064  # путь фиксируется сейчас, а не в момент выхода
    trap "rm -rf '$probe'" EXIT

    local out
    out="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$probe/probe.key.pem" 2>&1)" \
        || die_stand "openssl не генерирует ключ EC P-256: $out"
    out="$(openssl pkey -in "$probe/probe.key.pem" -pubout -out "$probe/probe.spki.pem" 2>&1)" \
        || die_stand "openssl не извлекает открытый ключ: $out"
    out="$(openssl req -x509 -key "$probe/probe.key.pem" -subj "/CN=probe" \
        -days 1 -out "$probe/probe.crt.pem" 2>&1)" \
        || die_stand "openssl не выписывает самоподписанный сертификат: $out"
    out="$(openssl pkcs12 -export -inkey "$probe/probe.key.pem" -in "$probe/probe.crt.pem" \
        -passout pass:probe -out "$probe/probe.p12" 2>&1)" \
        || die_stand "openssl не собирает контейнер PKCS#12: $out"

    rm -rf "$probe"
    trap - EXIT

    OPENSSL_VERSION="$(openssl version 2>/dev/null || echo "неизвестна")"
}

prepare_work_dir() {
    # В каталоге лежат приватные ключи выпуска, поэтому 0700 и root: доступ
    # посторонних к нему — не гигиена, а обход всей проверяемой гарантии.
    # Каталог пересоздаётся: остаток прошлого прогона может отличаться правами.
    rm -rf "$WORK_DIR"
    install -d -m 0700 -o root -g root "$WORK_DIR" \
        || die_stand "не создать рабочий каталог выпуска $WORK_DIR"
}

main() {
    require_root
    check_issuer
    check_openssl
    prepare_work_dir

    echo "issuer: $ISSUER_PATH ($ISSUER_VERSION)"
    echo "openssl: $OPENSSL_VERSION"
    echo "work dir: $WORK_DIR"
}

main "$@"
