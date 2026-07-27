#!/usr/bin/env bash
# deploy-fixtures.sh — раскладка тестовых удостоверений и конфигурации.
#
# Действие подготовки suite: раннер выполняет его один раз за прогон как
# `helpers/setup/deploy-fixtures.sh`.
#
# Сами удостоверения приезжают в окружение снаружи: это те же файлы, которыми
# пользуются unit-тесты (`crates/tessera_core/tests/fixtures/`), и вторая их
# копия в репозитории неминуемо разошлась бы с оригиналом. Скрипт проверяет,
# что доставка состоялась, и раскладывает производное от них: доверенный якорь,
# конфигурацию продукта и отдельный тестовый PAM-сервис.
#
# Системные PAM-стеки (`sudo`, `login`, `common-*`) НЕ трогаются: сервис
# `certauth` существует ровно для прогона, и сломать вход в окружение он не может.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

FIXTURES_DIR="${TESSERA_E2E_FIXTURES:-/opt/tessera-e2e/fixtures}"
# Если раннер положил фикстуры в другое место, они переносятся в канонический
# каталог: кейсы подставляют {{fixtures}} и о промежуточных путях не знают.
FIXTURES_SRC="${TESSERA_E2E_FIXTURES_SRC:-}"

CONFIG_DIR="/etc/tessera"
CA_DIR="$CONFIG_DIR/ca"
PAM_SERVICE="/etc/pam.d/certauth"

# Учётная запись входа — ролевая: имя учётной записи и есть запрашиваемая роль.
# Поэтому имя обязано совпадать с ролью, определение которой раскладывается в
# хранилище ниже, иначе резолв роли откажет по причине, не имеющей отношения к
# проверяемой гарантии. Удостоверения фикстур несут user_binding wildcard и
# allowed_roles, покрывающие эту роль.
E2E_USER="${TESSERA_E2E_USER:-serv}"

# Каталог ролевых фикстур (определения ролей и ролевые удостоверения). Раннер
# везёт его отдельно от фикстур ядра.
ROLES_FIXTURES_DIR="${TESSERA_E2E_ROLES:-/opt/tessera-e2e/roles}"
ROLE_STORE_DIR="/var/lib/tessera/roles"

EXIT_INTERNAL=70

# Файлы, без которых ни один кейс не поедет. Список намеренно явный:
# «фикстура не доставлена» должно звучать до первого кейса, а не внутри него.
REQUIRED_FIXTURES=(
    ca.pem
    int.pem
    leaf_rsa.p12
    expired_leaf.p12
    revoked_leaf.p12
    leaf_no_user_binding.p12
    crl_valid.pem
)

die_stand() {
    echo "deploy-fixtures: $*" >&2
    exit "$EXIT_INTERNAL"
}

require_root() {
    [ "$(id -u)" = "0" ] || die_stand "требуются права root"
}

import_fixtures() {
    [ -n "$FIXTURES_SRC" ] || return 0
    [ -d "$FIXTURES_SRC" ] || die_stand "каталог источника фикстур не найден: $FIXTURES_SRC"
    mkdir -p "$FIXTURES_DIR"
    cp -a "$FIXTURES_SRC"/. "$FIXTURES_DIR"/
}

check_fixtures() {
    [ -d "$FIXTURES_DIR" ] || die_stand \
        "каталог фикстур не найден: $FIXTURES_DIR. Фикстуры доставляет раннер до первого кейса"
    local missing=() name
    for name in "${REQUIRED_FIXTURES[@]}"; do
        [ -s "$FIXTURES_DIR/$name" ] || missing+=("$name")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die_stand "не доставлены фикстуры: ${missing[*]} (каталог $FIXTURES_DIR)"
    fi
}

deploy_trust() {
    mkdir -p "$CA_DIR"
    # Якорь — корневой УЦ фикстур. Промежуточный кладётся отдельным файлом:
    # в .p12 он присутствует, но полагаться на это в конфигурации не стоит —
    # кейс с цепочкой должен проверять доверие, а не удачную упаковку контейнера.
    install -m 0644 "$FIXTURES_DIR/ca.pem" "$CA_DIR/bundle.pem"
    install -m 0644 "$FIXTURES_DIR/int.pem" "$CA_DIR/intermediates.pem"
}

deploy_config() {
    mkdir -p "$CONFIG_DIR"
    # Конфигурация переписывается каждым прогоном целиком: подготовка обязана
    # приводить окружение к известному состоянию, а не дополнять предыдущее.
    # Кейсы отзыва подменяют этот файл своим и возвращают его в teardown.
    cat > "$CONFIG_DIR/config.toml" <<EOF
# Конфигурация e2e-прогона. Файл создаётся helpers/setup/deploy-fixtures.sh
# и перезаписывается на каждом прогоне — править его руками бессмысленно.

crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "certs/user.p12"

# Носитель в контейнерном профиле подключается мгновенно, ждать его незачем:
# лишнее ожидание превратило бы кейс «носителя нет» в кейс про таймаут.
usb_wait_seconds = 0
max_usb_partitions = 8
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
monitor_fail_mode = "permissive"

[trust]
anchors = ["$CA_DIR/bundle.pem"]
intermediates = ["$CA_DIR/intermediates.pem"]
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
# Базовое состояние — отзыв не проверяется. Кейсы отзыва подменяют режим
# и пути к CRL сами: держать здесь "crl" значило бы завалить все прочие
# кейсы по причине, к ним не относящейся.
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
# machine_id в контейнере может отсутствовать, hostname есть всегда.
sources = ["machine_id", "hostname"]
fallback = "deny"
custom_command_timeout_seconds = 5

# Удостоверения фикстур несут user_binding, и сопоставление берётся из него.
# Запись нужна для фикстуры без user_binding: она проверяет именно этот путь.
[[user_mapping]]
pam_user = "$E2E_USER"
cert_subject_cn = "$E2E_USER"

[roles]
dir = "$ROLE_STORE_DIR"

[logging]
level = "debug"
EOF
    chmod 0644 "$CONFIG_DIR/config.toml"
}

# Ролевое хранилище — такая же обязательная часть устройства, как якорь доверия:
# роль проверяется при каждом входе, и без хранилища не проходит ни один кейс,
# независимо от того, что он проверяет. Держать это в кейсах значило бы повторять
# одну и ту же подготовку в каждом и получать отказ резолва там, где проверяется
# совсем другое.
deploy_role_store() {
    local src="$ROLES_FIXTURES_DIR/store/$E2E_USER.toml"
    [ -s "$src" ] || die_stand \
        "не найдено определение роли $E2E_USER: $src (каталог ролевых фикстур везёт раннер)"
    # Хранилище доверяется по правам файловой системы (модель sudoers.d):
    # каталог и файлы обязаны принадлежать root, иначе продукт их отвергнет.
    install -d -m 0755 -o root -g root "$ROLE_STORE_DIR"
    install -m 0644 -o root -g root "$src" "$ROLE_STORE_DIR/$E2E_USER.toml"
}

deploy_pam_service() {
    # Отдельный сервис вместо правки системных стеков: прогон не должен
    # уметь сломать вход в окружение, а кейс интеграции проверяет
    # integrate-pam.sh отдельно и на своих файлах.
    cat > "$PAM_SERVICE" <<'EOF'
# Тестовый PAM-сервис e2e-контура. Создаётся helpers/setup/deploy-fixtures.sh.
# Системные стеки (sudo, login, common-*) прогоном не затрагиваются.
auth       [success=done default=die] pam_tessera.so
account    required                   pam_tessera.so
EOF
    chmod 0644 "$PAM_SERVICE"
}

ensure_user() {
    if id "$E2E_USER" >/dev/null 2>&1; then
        return 0
    fi
    command -v useradd >/dev/null 2>&1 || die_stand "не найден useradd, учётную запись $E2E_USER не создать"
    # Без пароля и без shell-логина: учётная запись нужна PAM-фазам как объект,
    # а не как способ войти в окружение.
    useradd --create-home --shell /usr/sbin/nologin "$E2E_USER" \
        || die_stand "не удалось создать учётную запись $E2E_USER"
}

main() {
    require_root
    import_fixtures
    check_fixtures
    ensure_user
    deploy_trust
    deploy_config
    deploy_role_store
    deploy_pam_service

    echo "fixtures: $FIXTURES_DIR"
    echo "config: $CONFIG_DIR/config.toml"
    echo "role store: $ROLE_STORE_DIR"
    echo "pam service: $PAM_SERVICE"
    echo "role account: $E2E_USER"
}

main "$@"
