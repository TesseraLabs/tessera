#!/usr/bin/env bash
# codes-phone.sh — телефонный канал входа по коду (режим 0) со стороны стенда.
#
# Хелпер исполняет роль, которую на объекте исполняет человек: он раскладывает на
# устройстве артефакты Codes, ведёт разговор PAM за инженера и, услышав challenge,
# идёт к оператору за кодом. Оператор здесь — консольная выдача `issuer codes issue`
# (change `codes-operator-cli`), и код считает ТОЛЬКО она: вторая реализация формулы
# в шелле разошлась бы с продуктом молча, а проявилось бы расхождение не в CI, а как
# «код не подходит» у инженера на объекте. Ради исключения этого заведён контрактный
# крейт, и хелпер этой границы не переходит.
#
#   codes-phone.sh prepare <fixtures>/codes [--without-codes-url]
#   codes-phone.sh authenticate <user> --level N
#   codes-phone.sh authenticate-with-code <user> --level N --code <код>
#   codes-phone.sh expect-issue-refused <user> --level N
#   codes-phone.sh exhaust-attempts <user>
#   codes-phone.sh replay-after-restart <user>
#   codes-phone.sh snapshot-counter
#   codes-phone.sh restore-counter
#   codes-phone.sh authenticate-without-code <user>
#   codes-phone.sh revoke-ticket
#   codes-phone.sh cleanup
#
# Разговор состоит из трёх ответов подряд («Оператор: », PIN контейнера, «Код: »), и
# третий вычисляется по тому, что модуль напечатал между вторым и первым. Поэтому
# ответы не подаются одним куском: драйвер запускается с `--answers-per-prompt`, его
# stdin — FIFO, и код кладётся туда уже после того, как challenge снят со stderr.
#
# Все команды идемпотентны, `cleanup` выполняется и там, где `prepare` не отработал:
# teardown кейса зовёт его при любом исходе.
#
# Каталог фикстур описывает сам себя файлом `device.env` — см. «Ожидаемые фикстуры»
# ниже. Без него хелперу пришлось бы угадывать номер устройства, эпоху и рамки, а
# несовпадение любого из них с материалом ключей выглядело бы как отказ продукта.

set -euo pipefail

PATH="/sbin:/usr/sbin:$PATH"
export PATH

# Служебные коды: 64 — ошибка вызова, 70 — сбой стенда. Профили перечисляют их в
# error_exit_codes, поэтому кейс отличит сломанный стенд от отказа продукта.
EXIT_USAGE=64
EXIT_INTERNAL=70

CONFIG="${TESSERA_E2E_CONFIG:-/etc/tessera/config.toml}"
# Эталон конфигурации снимается один раз, при первой правке, и живёт вне /run:
# cleanup обязан вернуть файл и после перезапуска окружения.
CONFIG_BACKUP=/var/lib/tessera/e2e-codes-config.orig
PAM_SERVICE="${TESSERA_E2E_CODES_PAM_SERVICE:-/etc/pam.d/codeauth}"
PAM_SERVICE_NAME="$(basename "$PAM_SERVICE")"

# Каталог артефактов устройства. Пишется в `[codes].dir` явно: дефолт продукта и
# дефолт хелпера обязаны быть одним значением, а не двумя совпадающими.
CODES_DIR="${TESSERA_E2E_CODES_DIR:-/var/lib/tessera/codes}"
STATE_DIR="$CODES_DIR/state"

# Состояние прогона — в /run: перезапуск окружения обнуляет его сам.
RUN_DIR="${TESSERA_E2E_STATE_DIR:-/run/tessera-e2e}/codes"
PREPARED="$RUN_DIR/prepared.env"
# Каталог квитанций выдачи. В нём же лежит хеш-цепочечный реестр выдач
# `ledger.ndjson`, и счётчик проверяется против ОБОИХ хранилищ — так закрыт
# обход, при котором история тихо обнулялась сменой каталога.
#
# Каталог и состояние устройства обнуляются ОДНОВРЕМЕННО, подкомандой prepare, и
# разъединять их нельзя: пустая история разрешает только начальный счётчик
# эпохи, поэтому обнулённая история при продолжающем счёт устройстве даст отказ
# выдачи на второй же попытке. Очистка идёт каталогом целиком — реестр попадает
# под неё вместе с квитанциями, и добавленное в каталог завтра попадёт тоже.
RECEIPTS_DIR="$RUN_DIR/receipts"
# Рабочая копия приватного ключа оператора: CLI требует от файла ключа прав
# 0600, а фикстуры приезжают с правами репозитория и правятся раннером до
# root:root, но не до 0600.
OPERATOR_KEY="$RUN_DIR/operator-key.pem"
# Снятый с устройства challenge — им работают команды, проверяющие сторону
# оператора.
CHALLENGE_FILE="$RUN_DIR/challenge.txt"

# Бюджет попыток ввода кода. Пишется в конфигурацию устройства явно (см.
# deploy_config): хелпер обязан подать РОВНО столько неверных кодов, сколько
# позволяет модуль, и единственный способ не разойтись — не полагаться на
# умолчание контракта с обеих сторон, а задать число в одном месте.
ATTEMPTS_PER_NONCE="${TESSERA_E2E_CODE_ATTEMPTS:-5}"

# Заведомо неверный код: восемь нулей — длина по умолчанию, десятичный алфавит,
# не сходится ни с каким общим ключом. Секретом не является.
WRONG_CODE="00000000"

die() {
    echo "codes-phone: $*" >&2
    exit "$EXIT_INTERNAL"
}

# Драйвер разговора живёт в фоне, и оборванный на середине хелпер оставил бы его
# висеть на FIFO до таймаута кейса. Убирается он одним обработчиком на выход:
# подстановки команд ($(...)) собственный EXIT не исполняют, поэтому живой
# разговор от них не пострадает.
DRIVER_PID=""
stop_driver() {
    [ -n "$DRIVER_PID" ] || return 0
    kill "$DRIVER_PID" 2>/dev/null || true
    DRIVER_PID=""
}
trap stop_driver EXIT

usage_error() {
    echo "codes-phone: $*" >&2
    usage
    exit "$EXIT_USAGE"
}

usage() {
    cat >&2 <<'EOF'
usage: codes-phone.sh <command> [args]
  prepare <fixtures>/codes [--without-codes-url]
                        разложить артефакты Codes, включить [codes] и завести
                        PAM-сервис codeauth
  authenticate <user> --level N
                        полный вход по коду: снять challenge, получить код у
                        `issuer codes issue`, подать его
  authenticate-with-code <user> --level N --code <код>
                        то же, но код задан снаружи и подаётся как есть;
                        выдача не вызывается вовсе
  expect-issue-refused <user> --level N
                        проверить, что выдача НЕ считает код на уровень вне
                        рамок билета; 0 только на отказ по рамкам
  exhaust-attempts <user>
                        исчерпать бюджет попыток ввода кода в одном прогоне
  replay-after-restart <user>
                        успешный вход, перезапуск устройства, тот же код снова
  snapshot-counter      снять копию файла счётчика nonce (как копия машины)
  restore-counter       вернуть снятую копию на место и перезапустить устройство;
                        0 только если счётчик успел уйти вперёд
  authenticate-without-code <user>
                        разговор, в котором код не подаётся вовсе: устройство
                        обязано отказать раньше, чем его спросит
  issue-storm <user> --level N --count M [--recover-after S]
                        M разговоров, обрываемых на напечатанном challenge, и
                        ещё один сверх того: устройство обязано отказать в
                        выдаче временно. С --recover-after выждать S секунд и
                        показать, что метод сам вернулся в строй
  revoke-ticket         дописать номер билета оператора в tickets.revoked
  cleanup               вернуть окружение как было (идемпотентно)
EOF
}

require_root() {
    [ "$(id -u)" = "0" ] || die "требуются права root"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "не найден инструмент: $1"
}

# ----------------------------------------------------------------------------
# Ожидаемые фикстуры: `<fixtures>/codes/`
#
# Каталог описывает сам себя, потому что хелперу нужны номер устройства, эпоха и
# рамки, а угаданное значение любого из них выглядело бы как отказ продукта.
# Материал сторон устройства и оператора разнесён по разным файлам намеренно: на
# объекте они лежат на разных машинах, и общий файл скрыл бы, что именно
# устройство знает об операторе.
#
# `device.env` — манифест каталога, оболочечные присваивания без экспорта:
#
#   DEVICE_NUMBER=...   номер устройства ВМЕСТЕ с контрольным символом ISO 7064
#                       MOD 37,36 (последний значащий символ). Ровно та строка,
#                       что попадёт в `[codes].device_number`: конфигурация
#                       отвергается, если символ не сходится.
#   EPOCH=...           номер эпохи ключа устройства, целое; та же эпоха, что у
#                       ключа в device.p12 и в записи устройства.
#   REGION=...          регион устройства; сверяется с рамками билета, поэтому
#                       обязан совпадать с регионом в operator-ticket.txt.
#   TAGS="dc-1 hq"      теги устройства через пробел, хотя бы один; билет
#                       достаёт устройство, если у них есть общий тег.
#   OPERATOR_ID=...     идентификатор оператора, которым хелпер представляется
#                       на промпте «Оператор: »; должен совпадать с оператором
#                       билета, иначе билет не найдётся.
#   TICKET_NUMBER=...   номер билета этого оператора; `revoke-ticket` дописывает
#                       его в tickets.revoked, поэтому формат — тот же, что
#                       читает список отзыва (одна строка, номер как есть).
#   DEVICE_KEY_PIN=...  PIN контейнера device.p12. Не секрет: фикстурный.
#   ORGANISATION_ID=... идентификатор организации, подписавшей запись устройства;
#                       выдача получает его как `--anchor-organisation <id>=<файл>`
#                       и обязана видеть ровно тот же id, что стоит в записи.
#
# Сторона устройства (кладётся в `[codes].dir` подкомандой prepare):
#
#   device.p12             PKCS#12 с ПРИВАТНЫМ ключом устройства той эпохи, что
#                          в EPOCH, под PIN из DEVICE_KEY_PIN. Профиль ключа —
#                          p256 (умолчание `[codes].profile`); из контейнера
#                          берётся только ключ.
#   tickets.txt            действующие билеты операторов, по одному документу
#                          контракта в строке — строка вида
#                          `tessera-codes/v1/ticket;operator=...;key=<hex SEC1>;
#                          tags=...;roles=...;region=...;max_level=...;
#                          not_after=...;number=...;signature=<hex DER>`.
#                          Среди них — билет оператора OPERATOR_ID.
#                          `not_after` — конечный, но с запасом в годы (в
#                          фикстурах 2031-01-01T00:00:00Z): момент выдачи ничем
#                          не подменяется (`--now` хелпер не передаёт), поэтому
#                          срок сверяется с часами стенда, и билет, истёкший к
#                          дню прогона, закрыл бы всю сюиту отказом, не имеющим
#                          отношения к проверяемому. Вечный билет в фикстуре
#                          учил бы неверному, поэтому срок именно конечный.
#   ticket-authority.pem   якорь билетов: SubjectPublicKeyInfo (PEM или DER)
#                          того ключа, ЧЬЕЙ подписью подписан каждый билет.
#                          Один и тот же файл читают обе стороны — устройство
#                          при проверке и выдача как `--anchor-ticket-authority`.
#
#   Списка отзыва в фикстурах НЕТ: прогон начинается с парка, где не отозвано
#   ничего, а CODE-007 создаёт tickets.revoked сам.
#
# Сторона оператора (остаётся в каталоге фикстур, читается только CLI):
#
#   operator-ticket.txt    тот же билет оператора OPERATOR_ID, что лежит в
#                          tickets.txt, отдельным файлом — это то, что оператор
#                          предъявляет своей выдаче. Рамки: регион REGION, хотя
#                          бы один тег из TAGS, роль-учётная запись прогона и
#                          потолок уровня 1 — CODE-006 требует, чтобы уровень 2
#                          билет НЕ покрывал.
#   operator-key.pem       приватный ключ оператора в PKCS#8 (PEM или DER),
#                          P-256, БЕЗ пароля. Его открытая половина обязана
#                          совпадать с `key=` в билете — иначе выдача откажет
#                          явной ошибкой несовпадения ключа, а не «код не
#                          подошёл». Софт-хранилище задаётся самим `--soft-key`,
#                          отдельного включающего флага нет; хелпер работает не
#                          с этим файлом, а с его копией под правами 0600.
#   device-record.txt      запись устройства, одна строка вида
#                          `tessera-codes/v1/device-record;device=<номер с
#                          контрольным символом>;key=<hex SEC1 открытого ключа
#                          устройства>;epoch=<u32>;organisation=<ORGANISATION_ID>;
#                          organisation_signature=<hex DER>;
#                          possession_signature=<hex DER>`. Обе подписи — ECDSA
#                          (P-256 или P-384) над SHA-256: организация подписывает
#                          канонические байты тела, PoP делается приватным ключом
#                          устройства над теми же байтами с доменным префиксом.
#                          `key=` — открытая половина ключа из device.p12,
#                          `epoch` — EPOCH, `device` — DEVICE_NUMBER.
#   organisation-anchor.pem  SubjectPublicKeyInfo (PEM или DER) организации
#                          ORGANISATION_ID — им проверяется подпись записи.
#
# Собрать это openssl'ом нельзя: билет, запись устройства и их подписи —
# документы контракта (`tessera_codes_contract`), и генератор обязан идти через
# него, иначе разойдётся с тем, что читает устройство. Готового генератора
# сегодня нет ни в CLI, ни в xtask: комплект собирается только Rust-фикстурами
# (`crates/tessera_issuer/src/codes/tests.rs`), и для шелла это не годится.
# ----------------------------------------------------------------------------

MANIFEST_VARS=(DEVICE_NUMBER EPOCH REGION TAGS OPERATOR_ID TICKET_NUMBER DEVICE_KEY_PIN
    ORGANISATION_ID)

DEVICE_FILES=(device.p12 tickets.txt ticket-authority.pem)
OPERATOR_FILES=(operator-ticket.txt operator-key.pem device-record.txt organisation-anchor.pem)

load_manifest() {
    local dir="$1" name
    [ -d "$dir" ] || die "каталог фикстур телефонного канала не найден: $dir"
    [ -f "$dir/device.env" ] || die \
        "нет манифеста $dir/device.env — хелперу нечем узнать номер устройства, эпоху и рамки"
    # shellcheck disable=SC1091  # файл фикстур, его содержимое известно только в прогоне
    . "$dir/device.env"
    for name in "${MANIFEST_VARS[@]}"; do
        [ -n "${!name:-}" ] || die "в $dir/device.env не задан $name"
    done
    local missing=()
    for name in "${DEVICE_FILES[@]}" "${OPERATOR_FILES[@]}"; do
        [ -s "$dir/$name" ] || missing+=("$name")
    done
    [ "${#missing[@]}" -eq 0 ] || die "в $dir не хватает файлов: ${missing[*]}"
    FIXTURES_CODES_DIR="$dir"
}

# Состояние prepare переживает границу шагов кейса: authenticate и остальные
# команды вызываются отдельными процессами и о каталоге фикстур не знают.
save_prepared() {
    install -d -m 0700 "$RUN_DIR"
    {
        printf 'FIXTURES_CODES_DIR=%q\n' "$FIXTURES_CODES_DIR"
        printf 'DEVICE_NUMBER=%q\n' "$DEVICE_NUMBER"
        printf 'EPOCH=%q\n' "$EPOCH"
        printf 'REGION=%q\n' "$REGION"
        printf 'TAGS=%q\n' "$TAGS"
        printf 'OPERATOR_ID=%q\n' "$OPERATOR_ID"
        printf 'TICKET_NUMBER=%q\n' "$TICKET_NUMBER"
        printf 'DEVICE_KEY_PIN=%q\n' "$DEVICE_KEY_PIN"
        printf 'ORGANISATION_ID=%q\n' "$ORGANISATION_ID"
        printf 'WITHOUT_CODES_URL=%q\n' "$WITHOUT_CODES_URL"
    } > "$PREPARED"
    chmod 0600 "$PREPARED"
}

load_prepared() {
    [ -f "$PREPARED" ] || die "подготовка не выполнялась: нет $PREPARED (нужен prepare)"
    # shellcheck disable=SC1090  # файл создаётся save_prepared этим же хелпером
    . "$PREPARED"
}

# ----------------------------------------------------------------------------
# prepare
# ----------------------------------------------------------------------------

deploy_artefacts() {
    local src="$FIXTURES_CODES_DIR"
    # Права ровно те, которых требует спека артефактов: контейнер ключа root-only,
    # каталог закрыт. Ослабленные права продукт обязан заметить сам, и кейс,
    # стартовавший с 0644, проверял бы поведение стенда.
    install -d -m 0700 -o root -g root "$CODES_DIR"
    # ВНИМАНИЕ: этот шаг устарел и будет красным. Устройство больше не открывает
    # контейнер паролем — `[codes].key_password` убран, ключ в хранилище лежит
    # БЕЗ пароля, а PIN остался формой доставки. `device.p12` из комплекта фикстур
    # закрыт PIN'ом (DEVICE_KEY_PIN), поэтому положенный сюда как есть он не
    # откроется, и кейсы CODE-* упадут на материале ключа, а не на проверяемой
    # гарантии. Чинится одним из двух способов, оба вне этой волны: раскладывать
    # ключ продуктовым импортом (`tessera enroll --codes-pin-file`), как это
    # делает helpers/codes-enroll.sh, либо научить `cargo xtask codes-fixtures`
    # класть рядом хранимую форму контейнера (без пароля). Записано в BASELINE.md.
    install -m 0600 -o root -g root "$src/device.p12" "$CODES_DIR/device.p12"
    install -m 0644 -o root -g root "$src/tickets.txt" "$CODES_DIR/tickets.txt"
    install -m 0644 -o root -g root "$src/ticket-authority.pem" \
        "$CODES_DIR/ticket-authority.pem"
    # Список отзыва — состояние кейса, а не фикстура: прогон начинается с парка,
    # где не отозвано ничего, а CODE-007 отзывает билет сам.
    rm -f "$CODES_DIR/tickets.revoked"
    # Счётчик nonce и потреблённые значения — тоже состояние: кейс обязан начинать
    # с чистого устройства, иначе одноразовость прошлого кейса закроет этот.
    rm -rf "$STATE_DIR"
    install -d -m 0700 -o root -g root "$STATE_DIR"
}

# Приватный ключ оператора кладётся рядом с прогоном под правами 0600: выдача
# отказывается работать с файлом ключа, доступным кому-то ещё. Копия нужна даже
# после того, как генератор фикстур стал выставлять 0600 сам: git хранит из прав
# только бит исполнения, поэтому в свежем клоне и в CI файл появится с 0644 по
# umask, а прогон обязан работать и там. Оригинал не трогаем — он общий для всех
# прогонов и лежит в дереве репозитория.
stage_operator_key() {
    install -m 0600 -o root -g root "$FIXTURES_CODES_DIR/operator-key.pem" "$OPERATOR_KEY"
}

# Секция дописывается в конец файла целиком. Это секция, а не ключ верхнего
# уровня: её место в файле значения не имеет, чего нельзя сказать о ключе
# (см. config-mutate.sh).
deploy_config() {
    [ -f "$CONFIG" ] || die "нет конфигурации $CONFIG — подготовка suite не отработала"
    [ -f "$CONFIG_BACKUP" ] || cp "$CONFIG" "$CONFIG_BACKUP"

    local tags_toml="" tag
    for tag in $TAGS; do
        [ -z "$tags_toml" ] || tags_toml+=", "
        tags_toml+="\"$tag\""
    done

    # Правка идёт на копии и встаёт на место одним mv: оборванный прогон не должен
    # оставлять на неодноразовой машине усечённый /etc/tessera/config.toml.
    local staging="$CONFIG.e2e-codes"
    {
        # Прошлый prepare мог уже дописать секцию — берём эталон, а не текущий файл.
        cat "$CONFIG_BACKUP"
        cat <<EOF

# Секция телефонного канала. Дописывается helpers/codes-phone.sh на время кейса
# и снимается его же cleanup.
[codes]
enabled = true
dir = "$CODES_DIR"
device_number = "$DEVICE_NUMBER"
epoch = $EPOCH
region = "$REGION"
tags = [$tags_toml]
# Бюджет попыток задан явно: хелпер подаёт ровно его в exhaust-attempts, и
# умолчание контракта не должно расходиться с тем, что считает хелпер.
attempts_per_nonce = $ATTEMPTS_PER_NONCE
EOF
    } > "$staging"
    chmod --reference="$CONFIG" "$staging"
    chown --reference="$CONFIG" "$staging"
    mv -f "$staging" "$CONFIG"
}

# Режим 0 самодостаточен: он не требует ни сети, ни сайта выдачи. Проверять это
# нечем, кроме отсутствия соответствующей конфигурации, поэтому флаг не «не
# настраивай URL» (его и так никто не настраивает), а «убедись, что ни одного
# Codes-URL в конфигурации нет». Сегодня в схеме `[codes]` такого ключа нет
# вовсе, и проверка сторожит будущее: ключ, появившийся со значением по
# умолчанию, тихо превратил бы кейс «устройство без серверной конфигурации» в
# кейс про устройство с ней.
assert_no_codes_url() {
    if sed -n '/^\[codes\]/,/^\[/p' "$CONFIG" | grep -qiE '^[^#]*url'; then
        die "в секции [codes] есть Codes-URL, а кейс проверяет работу без него"
    fi
}

deploy_pam_service() {
    # Отдельный сервис, как и certauth: системные стеки прогоном не затрагиваются.
    cat > "$PAM_SERVICE" <<'EOF'
# Тестовый PAM-сервис телефонного канала. Создаётся helpers/codes-phone.sh и
# снимается его cleanup. Системные стеки (sudo, login, common-*) не затрагиваются.
auth       [success=done default=die] pam_tessera.so method=code
# Фазы account и session метода не выбирают: учётная запись входа — ролевая, и
# после успешной auth они идут тем же путём, что в certauth.
account    required                   pam_tessera.so
session    required                   pam_tessera.so
EOF
    chmod 0644 "$PAM_SERVICE"
}

cmd_prepare() {
    local dir="" flag
    WITHOUT_CODES_URL=0
    for flag in "$@"; do
        case "$flag" in
            --without-codes-url) WITHOUT_CODES_URL=1 ;;
            -*) usage_error "неизвестный флаг prepare: $flag" ;;
            *)
                [ -z "$dir" ] || usage_error "prepare принимает один каталог фикстур"
                dir="$flag"
                ;;
        esac
    done
    [ -n "$dir" ] || usage_error "usage: codes-phone.sh prepare <fixtures>/codes [--without-codes-url]"

    require_root
    require_tool install
    load_manifest "$dir"

    deploy_artefacts
    deploy_config
    [ "$WITHOUT_CODES_URL" -eq 0 ] || assert_no_codes_url
    deploy_pam_service

    install -d -m 0700 "$RUN_DIR"
    stage_operator_key
    # История выдач (квитанции И реестр `ledger.ndjson`) обнуляется вместе с
    # состоянием устройства — см. deploy_artefacts: счётчик выдач и счётчик
    # nonce на устройстве суть две записи об одной последовательности, и
    # разъехавшись они дают отказ выдачи там, где кейс проверяет совсем другое.
    rm -rf "$RECEIPTS_DIR"
    install -d -m 0700 "$RECEIPTS_DIR"
    save_prepared

    echo "codes: $CODES_DIR"
    echo "config: $CONFIG"
    echo "pam service: $PAM_SERVICE"
    echo "device: $DEVICE_NUMBER epoch $EPOCH region $REGION tags $TAGS"
}

# ----------------------------------------------------------------------------
# Оператор: выдача кода консольной командой
# ----------------------------------------------------------------------------

# Устройство печатает challenge в форме для диктовки — шесть полей через « / »,
# номер и nonce разбиты на группы по три символа, потому что длинный прогон цифр
# человек перевирает. Оператор набирает у себя ровно то, что услышал; здесь
# набор и происходит: пробелы внутри групп убираются, поля раскладываются по
# ключам проводной формы контракта в её единственном порядке.
#
# Второй аргумент — уровень, которым перебивается услышанное поле. Он нужен
# ровно одному кейсу: проверке, что выдача не считает код за пределами рамок
# билета. Метку процесса на системе без мандатного механизма не поднять, а для
# выдачи challenge — это строка, которую ей продиктовали, и рамки она проверяет
# по ней. Подмена уровня здесь и есть проверяемый ввод; на устройство этот
# challenge не возвращается.
wire_from_spoken() {
    local spoken="$1" level_override="${2:-}"
    local IFS='/'
    # shellcheck disable=SC2206  # разбиение по разделителю полей — здесь оно и нужно
    local fields=($spoken)
    [ "${#fields[@]}" -eq 6 ] || die "challenge не разобрался в шесть полей: $spoken"
    local trimmed=() field
    for field in "${fields[@]}"; do
        # Пробелы группировки и обрамления снимаются целиком; внутри значений
        # контракта пробела быть не может — проводная форма его не несёт.
        trimmed+=("$(printf '%s' "$field" | tr -d '[:space:]')")
    done
    [ -z "$level_override" ] || trimmed[4]="$level_override"
    printf 'tessera-codes/v1/challenge;device=%s;epoch=%s;nonce=%s;role=%s;level=%s;operator=%s' \
        "${trimmed[0]}" "${trimmed[1]}" "${trimmed[2]}" \
        "${trimmed[3]}" "${trimmed[4]}" "${trimmed[5]}"
}

# Единственное место, где хелпер обращается к выдаче. Если интерфейс CLI
# изменится, правится только эта функция — и нигде в хелпере нет ветки, которая
# посчитала бы код сама, когда команда недоступна: молчаливый обход контракта
# хуже красного кейса.
#
# Печатает stdout выдачи, диагностику кладёт в $1, возвращает её код возврата.
run_issue() {
    local err_file="$1" wire="$2"
    command -v issuer >/dev/null 2>&1 || die \
        "не найден issuer — код выдаёт только 'issuer codes issue', своей формулы у хелпера нет"

    # Ключ оператора берётся из копии с правами 0600 (см. stage_operator_key):
    # владельческий гейт CLI отвергает файл, доступный кому-то ещё, а фикстуры
    # приезжают с правами репозитория.
    issuer codes issue \
        --challenge "$wire" \
        --device-record "$FIXTURES_CODES_DIR/device-record.txt" \
        --ticket "$FIXTURES_CODES_DIR/operator-ticket.txt" \
        --anchor-ticket-authority "$FIXTURES_CODES_DIR/ticket-authority.pem" \
        --anchor-organisation "$ORGANISATION_ID=$FIXTURES_CODES_DIR/organisation-anchor.pem" \
        --soft-key "$OPERATOR_KEY" \
        --receipts "$RECEIPTS_DIR" \
        --reason "e2e $PAM_SERVICE_NAME" \
        --code-only 2> "$err_file"
}

# Выдача для входа: код или смерть. Отказ выдачи здесь — сбой стенда: кейсы
# входа предъявляют устройству код, и не получить его значит не дойти до
# проверяемой гарантии.
issue_code() {
    local wire="$1"
    local err="$RUN_DIR/issue.err"
    local out rc=0
    out="$(run_issue "$err" "$wire")" || rc=$?
    if [ "$rc" -ne 0 ]; then
        cat "$err" >&2
        # Класс отказа называется прямо в диагностике: без него разбор упавшего
        # кейса начинается с чтения локализованного текста, а он говорит человеку
        # у телефона, а не тому, кто разбирает прогон.
        die "issuer codes issue вернул $rc ($(issue_outcome "$rc")/$(issue_refusal_class "$err")) для challenge: $wire"
    fi
    # `--code-only` печатает ровно одну строку — сам код. Разбирать тут нечего, и
    # разбор был бы вреден: догадка о формате вывода — тот же обход контракта,
    # что и своя формула, только по другому месту.
    printf '%s' "$out"
}

# Параметры парка (длина кода, ширины счётчика и хвоста, алфавит, профиль) не
# передаются: стенд идёт на умолчаниях контракта, и они же стоят в `[codes]`.
# Как только кейсу понадобится нестандартный парк, значения обязаны приехать
# сюда и в конфигурацию из ОДНОГО источника — разошедшиеся половины дают
# «код не подходит» без объяснения.

# ----------------------------------------------------------------------------
# Разговор PAM
# ----------------------------------------------------------------------------

# Уровень МКЦ приходит из метки процесса, а не из аргумента: его читает сам
# модуль. Значит, прогон на запрошенный уровень — это прогон процесса с такой
# меткой, и подменить её изнутри хелпера нечем. Если стенд умеет запускать
# команду на заданном уровне, он говорит об этом шаблоном в TESSERA_E2E_LEVEL_EXEC
# ({level} подставляется). Не умеет и уровень не совпадает с текущим — это отказ
# стенда, а не продукта: молча прогнать на уровне 0 кейс про уровень 2 значит
# получить зелёный, ничего не проверивший.
current_level() {
    local label
    if [ -r /proc/self/attr/current ]; then
        label="$(tr -d '\0' < /proc/self/attr/current)"
    fi
    if [ -n "${label:-}" ]; then
        printf '%s' "$label" | cut -d: -f2
    else
        # Метки нет — системы без мандатного механизма работают на уровне 0
        # по построению (см. codes_level).
        printf '0'
    fi
}

level_prefix() {
    local level="$1" now
    now="$(current_level)"
    if [ "$level" = "$now" ]; then
        return 0
    fi
    if [ -n "${TESSERA_E2E_LEVEL_EXEC:-}" ]; then
        printf '%s' "${TESSERA_E2E_LEVEL_EXEC//\{level\}/$level}"
        return 0
    fi
    die "процесс идёт на уровне $now, а кейсу нужен $level; стенд не умеет ставить уровень (нет TESSERA_E2E_LEVEL_EXEC) — нужен профиль с mac"
}

# Ведёт один разговор целиком и возвращает его код.
#
# Ответы подаются в FIFO по мере промптов: код третьего ответа существует только
# после того, как модуль напечатал challenge, а challenge появляется на stderr
# драйвера уже после первого ответа. Один поток stdin здесь не годится — драйвер
# для того и умеет `--answers-per-prompt`.
#
# $1 — учётная запись, $2 — уровень, $3 — как получить коды: `issue` (спросить
# оператора), `wrong` (заведомо неверный), либо `fixed:<код>`; $4 — сколько раз
# отвечать на промпт кода.
run_conversation() {
    local user="$1" level="$2" source="$3" code_answers="$4"
    local prefix
    prefix="$(level_prefix "$level")"

    install -d -m 0700 "$RUN_DIR"
    local fifo="$RUN_DIR/conv.in"
    local out="$RUN_DIR/conv.out"
    local err="$RUN_DIR/conv.err"
    rm -f "$fifo" "$out" "$err"
    mkfifo -m 0600 "$fifo"

    # shellcheck disable=SC2086  # prefix — команда с аргументами, разбиение намеренно
    $prefix pam-drive --answers-per-prompt "$PAM_SERVICE_NAME" "$user" authenticate \
        < "$fifo" > "$out" 2> "$err" &
    local driver=$!
    DRIVER_PID="$driver"

    # FIFO открывается на запись после запуска читателя и держится открытым до
    # конца разговора: закрытый дескриптор — это EOF, а EOF на промпте драйвер
    # считает ошибкой разговора.
    exec 3> "$fifo"
    printf '%s\n' "$OPERATOR_ID" >&3
    printf '%s\n' "$DEVICE_KEY_PIN" >&3

    local code=""
    case "$source" in
        issue)
            local spoken
            spoken="$(await_challenge "$err" "$driver")"
            code="$(issue_code "$(wire_from_spoken "$spoken")")"
            [ -n "$code" ] || die "выдача не вернула код (см. $err)"
            printf '%s\n' "$code" > "$RUN_DIR/last-code"
            ;;
        wrong) code="$WRONG_CODE" ;;
        fixed:*) code="${source#fixed:}" ;;
        *) die "неизвестный источник кода: $source" ;;
    esac

    local i
    for ((i = 0; i < code_answers; i++)); do
        printf '%s\n' "$code" >&3
    done
    exec 3>&-

    local rc=0
    wait "$driver" || rc=$?
    DRIVER_PID=""
    rm -f "$fifo"

    # Вывод драйвера прокидывается как есть: кейс пишет ожидания по его строкам,
    # и переписанный здесь вердикт означал бы, что кейс проверяет хелпер.
    cat "$out"
    cat "$err" >&2
    return "$rc"
}

# Ведёт разговор только до напечатанного challenge и обрывает его. Нужен там,
# где проверяется сторона оператора: устройство обязано выдать настоящий
# challenge (со своим счётчиком и nonce), а вердикт входа к делу не относится.
# Обрыв — закрытый stdin: драйвер сообщит об оборванном разговоре, и это
# ожидаемо, поэтому его код возврата здесь не читается.
#
# Результат кладётся в файл, а не в stdout: функция зовётся не подстановкой,
# чтобы фоновый драйвер оставался виден обработчику выхода (см. stop_driver).
capture_challenge() {
    local user="$1"
    install -d -m 0700 "$RUN_DIR"
    local fifo="$RUN_DIR/conv.in"
    local out="$RUN_DIR/conv.out"
    local err="$RUN_DIR/conv.err"
    rm -f "$fifo" "$out" "$err"
    mkfifo -m 0600 "$fifo"

    pam-drive --answers-per-prompt "$PAM_SERVICE_NAME" "$user" authenticate \
        < "$fifo" > "$out" 2> "$err" &
    DRIVER_PID=$!

    exec 3> "$fifo"
    printf '%s\n' "$OPERATOR_ID" >&3
    printf '%s\n' "$DEVICE_KEY_PIN" >&3

    local spoken
    spoken="$(await_challenge "$err" "$DRIVER_PID")"
    exec 3>&-
    wait "$DRIVER_PID" 2>/dev/null || true
    DRIVER_PID=""
    rm -f "$fifo"

    printf '%s\n' "$spoken" > "$CHALLENGE_FILE"
}

# Ждёт напечатанный challenge на stderr драйвера. Строка приходит внутри
# PAM_TEXT_INFO, следом за строкой «Продиктуйте оператору:», и содержит шесть
# полей через « / ». Ожидание ограничено: разговор, застрявший до промпта кода,
# обязан кончиться диагностикой, а не висеть до таймаута кейса.
await_challenge() {
    local err="$1" driver="$2" waited=0
    local limit="${TESSERA_E2E_CHALLENGE_TIMEOUT:-30}"
    while :; do
        local line
        line="$(grep -m1 -E ' / .* / .* / .* / .* / ' "$err" 2>/dev/null || true)"
        if [ -n "$line" ]; then
            printf '%s' "$line"
            return 0
        fi
        kill -0 "$driver" 2>/dev/null || die "драйвер завершился, не напечатав challenge (см. $err)"
        sleep 0.2
        waited=$((waited + 1))
        [ "$waited" -lt $((limit * 5)) ] || die "challenge не появился за ${limit} с (см. $err)"
    done
}

# ----------------------------------------------------------------------------
# Команды разговора
# ----------------------------------------------------------------------------

cmd_authenticate() {
    local user="${1:-}" level=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент authenticate: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] \
        || usage_error "usage: codes-phone.sh authenticate <user> --level N"

    load_prepared
    run_conversation "$user" "$level" issue 1
}

# Тот же вход, но код приходит аргументом и подаётся как есть: выдача не
# вызывается вовсе, и в кейсе это видно по имени команды, а не по флагу.
#
# Код повторяется на весь бюджет попыток намеренно. Цикл переспроса живёт в
# модуле: неверный код он спрашивает заново, пока бюджет не кончится, а одна
# строка оборвала бы разговор на втором промпте ошибкой драйвера. Ошибка
# разговора отдаётся тем же PAM_AUTH_ERR, что и отказ по коду, — кейс не отличил
# бы сбой стенда от вердикта продукта и зеленел бы по неверной причине.
cmd_authenticate_with_code() {
    local user="${1:-}" level="" code=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            --code)
                code="${2:-}"
                shift 2 || usage_error "--code без значения"
                ;;
            *) usage_error "неизвестный аргумент authenticate-with-code: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] && [ -n "$code" ] \
        || usage_error "usage: codes-phone.sh authenticate-with-code <user> --level N --code <код>"

    load_prepared
    run_conversation "$user" "$level" "fixed:$code" "$ATTEMPTS_PER_NONCE"
}

# Класс отказа выдачи. Отделяет «запрос вне рамок билета» — единственный отказ,
# который для кейса означает работающую гарантию, — от всех прочих: нет файла,
# битая подпись, ключ оператора не тот, что в билете, кривой challenge. Без
# этого различения кейс зеленел бы на сломанном стенде, а это хуже красного:
# сломанный стенд молчит ровно там, где должен кричать.
#
# Различение идёт по коду возврата и по первой строке stderr, а не по тексту
# сообщения: текст локализован, и ожидание, написанное по русской строке,
# отвалилось бы на первой же правке формулировки. Коды возврата выдачи
# (`issuer codes issue --help` несёт ту же таблицу):
#
#   0  код выдан
#   10 вне рамок билета — устройство, эпоха, оператор, регион, метки, роль, уровень
#   11 счётчик не сходится с историей выдач (опережает, отстаёт, повторён)
#   12 не сошлись подписи или доверие
#   13 выдача без основания
#   14 прочий отказ выдачи, включая неразобравшийся challenge
#   1  ПРОВЕРКА НЕ СОСТОЯЛАСЬ — нет файла, документ не разобрался, ключ
#      недоступен, порвана цепочка реестра выдач (`ledger_unusable`)
#
# Единица — не вердикт: до ответа не дошло. Именно она отделяет сломанный стенд
# от отказа продукта, и путать их нельзя ни в одну сторону.
#
# При любом отказе первой строкой stderr идёт `codes-refusal: <класс>`. Класс
# точнее кода (у кода 10 их четыре — по осям рамок), стабилен и не переводится.
# Поэтому исход и класс читаются РАЗНЫМИ функциями: код говорит, состоялся ли
# вопрос, класс — что именно ответили. Слепив их, диагностика сбоя стенда
# перестала бы называть причину («реестр порван» превратилось бы в «не дошло»).
ISSUE_EXIT_TOOL_FAILURE=1
ISSUE_EXIT_TICKET_SCOPE=10

issue_outcome() {
    local rc="$1"
    case "$rc" in
        0) echo issued ;;
        "$ISSUE_EXIT_TOOL_FAILURE") echo tool ;;
        *) echo refused ;;
    esac
}

issue_refusal_class() {
    local err_file="$1"
    local class
    class="$(sed -n 's/^codes-refusal: //p' "$err_file" | head -1)"
    printf '%s\n' "${class:-unknown}"
}

# Проверка стороны оператора: код за пределами рамок билета не выдаётся вовсе.
#
# Устройство даёт настоящий challenge, в нём подменяется поле уровня — это и
# есть то, что оператору диктуют, когда инженер сидит в сессии запрошенного
# уровня. Поднять метку процесса на стенде без мандатного механизма нельзя, а
# проверяемая здесь граница целиком на стороне выдачи: она сверяет рамки билета
# по продиктованному, до всякого вычисления.
#
# Ноль возвращается ТОЛЬКО на отказ по рамкам. Выданный код — провал гарантии;
# отказ по любой другой причине — сбой стенда.
cmd_expect_issue_refused() {
    local user="${1:-}" level=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент expect-issue-refused: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] \
        || usage_error "usage: codes-phone.sh expect-issue-refused <user> --level N"

    load_prepared
    capture_challenge "$user"

    local wire
    wire="$(wire_from_spoken "$(cat "$CHALLENGE_FILE")" "$level")"

    local err="$RUN_DIR/issue.err" rc=0
    # Код выдачи не печатается никуда: если гарантия нарушена, важен сам факт,
    # а лог кейса переживает прогон и уезжает в артефакты.
    run_issue "$err" "$wire" > /dev/null || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "codes-phone: выдача посчитала код на уровень $level, которого билет не покрывает" >&2
        return 1
    fi

    local class outcome
    class="$(issue_refusal_class "$err")"
    outcome="$(issue_outcome "$rc")"
    if [ "$outcome" = tool ]; then
        # Вопрос не состоялся: нет файла, документ не разобрался, порван реестр
        # выдач. Класс называется в диагностике — «стенд не разложили» должно
        # звучать именно так, а не «выдача чем-то недовольна».
        cat "$err" >&2
        die "выдача не дошла до ответа ($class, код $rc) — сбой стенда, а не проверенная гарантия"
    fi
    case "$class" in
        ticket_scope_level)
            # Код возврата сверяется с классом: они говорят об одном и том же
            # разными словами, и разойтись могут только дефектом выдачи —
            # такой разлад кейс обязан заметить, а не принять за успех.
            [ "$rc" = "$ISSUE_EXIT_TICKET_SCOPE" ] || die \
                "класс отказа $class, а код возврата $rc вместо $ISSUE_EXIT_TICKET_SCOPE — выдача противоречит сама себе"
            echo "выдача отказала по потолку уровня в билете: $class"
            return 0
            ;;
        ticket_scope_*)
            # Рамки не покрыли запрос по ДРУГОЙ оси — регион, теги, роль. Отказ
            # настоящий, но не тот, что проверяет кейс: значит разошлись рамки
            # билета и описание устройства в фикстурах, и до проверки потолка
            # уровня дело не дошло.
            cat "$err" >&2
            die "выдача отказала по оси $class, а кейс проверяет потолок уровня — фикстура и устройство описывают разные рамки"
            ;;
        *)
            cat "$err" >&2
            die "выдача отказала классом $class — это не отказ по рамкам билета, гарантия не проверена"
            ;;
    esac
}

# Бюджет попыток тратится ВНУТРИ одного разговора: цикл переспроса живёт в
# модуле, и прогон, запускающий драйвер по разу на попытку, проверял бы вместо
# бюджета счётчик, которого нет. Уровень берётся текущий: кейс про исчерпание
# попыток про уровень ничего не утверждает.
cmd_exhaust_attempts() {
    local user="${1:-}"
    [ -n "$user" ] || usage_error "usage: codes-phone.sh exhaust-attempts <user>"
    load_prepared
    run_conversation "$user" "$(current_level)" wrong "$ATTEMPTS_PER_NONCE"
}

# Перезапуск устройства между вводами: службы поднимаются заново, состояние в
# /run пропадает, а потреблённые nonce лежат на диске и обязаны пережить это.
# Настоящей перезагрузки в контейнере нет, поэтому проверяется ровно то, что
# проверить можно: переживание рестарта служб и потери кэшей в памяти.
restart_device() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart tessera || die "не удалось перезапустить службу tessera"
        local i
        for ((i = 0; i < 50; i++)); do
            [ -S /run/tessera/monitord.sock ] && break
            sleep 0.2
        done
    fi
    # Кэши страниц сбрасываются, чтобы прочитанное после рестарта приходило с
    # диска, а не из памяти ядра. Недоступность ручки — не повод падать: на
    # состояние продукта она не влияет.
    sync
    [ -w /proc/sys/vm/drop_caches ] && echo 3 > /proc/sys/vm/drop_caches || true
}

cmd_replay_after_restart() {
    local user="${1:-}"
    [ -n "$user" ] || usage_error "usage: codes-phone.sh replay-after-restart <user>"
    load_prepared

    local level
    level="$(current_level)"
    run_conversation "$user" "$level" issue 1 \
        || die "первый вход по коду не прошёл — повторять нечего"

    local code
    code="$(cat "$RUN_DIR/last-code")"
    [ -n "$code" ] || die "код первого входа не сохранился"

    restart_device

    # Тот же код подаётся на все попытки нового разговора: модуль спрашивает код
    # по бюджету, и одна строка оборвала бы разговор ошибкой драйвера вместо
    # вердикта продукта.
    run_conversation "$user" "$level" "fixed:$code" "$ATTEMPTS_PER_NONCE"
}

# ----------------------------------------------------------------------------
# Откат персистированного состояния
# ----------------------------------------------------------------------------
#
# Счётчик выданных значений и состояние с потреблёнными nonce лежат РАЗНЫМИ
# файлами и пишутся раздельно, счётчик первым. Отсюда и наблюдаемость отката:
# счётчик, оказавшийся ПОЗАДИ состояния, означает, что вот-вот будут выданы
# значения, уже произнесённые вслух, — устройство обязано отказать целиком, а
# парк обязан провести смену эпохи ключа.
#
# Согласованный снимок (оба файла из одной копии) не детектируется ничем — так
# записано в модели угроз, и хелпер такого сценария не изображает: команда,
# «проверяющая» недетектируемое, зеленела бы по неверной причине.
COUNTER_FILE="$STATE_DIR/nonce.counter"
COUNTER_COPY="$RUN_DIR/nonce.counter.copy"

read_counter() {
    [ -f "$COUNTER_FILE" ] || { printf '0'; return 0; }
    tr -d '[:space:]' < "$COUNTER_FILE"
}

cmd_snapshot_counter() {
    require_root
    load_prepared
    [ -f "$COUNTER_FILE" ] || die \
        "нет $COUNTER_FILE — устройство не выдало ни одного challenge, откатывать будет нечего"
    install -d -m 0700 "$RUN_DIR"
    install -m 0600 -o root -g root "$COUNTER_FILE" "$COUNTER_COPY"
    echo "counter snapshot: $(read_counter)"
}

cmd_restore_counter() {
    require_root
    load_prepared
    [ -f "$COUNTER_COPY" ] || die "снимок не снят — нужен snapshot-counter"

    local before after
    before="$(tr -d '[:space:]' < "$COUNTER_COPY")"
    after="$(read_counter)"
    # Счётчик, не сдвинувшийся с момента снимка, — это не откат, а тот же файл:
    # устройство ничего не заметит и пустит, а кейс зазеленеет, ничего не
    # проверив. Разница между копией и текущим значением и есть предмет кейса.
    [ "$after" -gt "$before" ] || die \
        "счётчик не ушёл вперёд с момента снимка ($before → $after) — откатывать нечего"

    # Права те же, что ставит само устройство (0600, root): восстановленная из
    # копии машина не должна отличаться от настоящей ничем, кроме значения.
    install -m 0600 -o root -g root "$COUNTER_COPY" "$COUNTER_FILE"
    # Перезапуск — часть восстановления, а не украшение: владелец парка вернул
    # копию и поднял машину. Он же снимает вопрос о том, не держится ли отказ на
    # чём-то, что осталось в памяти процесса.
    restart_device
    echo "counter rolled back: $after -> $before"
}

# Разговор, в котором код не подаётся вовсе. Нужен там, где устройство обязано
# отказать ДО промпта кода: подавать ответы в разговор, которого не будет,
# нечем, а `authenticate` в таком прогоне упёрся бы в ненапечатанный challenge и
# отдал сбой стенда (70) вместо вердикта продукта.
#
# Ответы кладутся в FIFO с ограничением по времени и без проверки исхода записи:
# оборванная труба здесь — ожидаемый ход событий, а не сбой. Кейсу отдаётся код
# возврата драйвера как есть.
cmd_authenticate_without_code() {
    local user="${1:-}"
    [ -n "$user" ] || usage_error "usage: codes-phone.sh authenticate-without-code <user>"
    load_prepared

    install -d -m 0700 "$RUN_DIR"
    local fifo="$RUN_DIR/conv.in"
    local out="$RUN_DIR/conv.out"
    local err="$RUN_DIR/conv.err"
    rm -f "$fifo" "$out" "$err"
    mkfifo -m 0600 "$fifo"

    pam-drive --answers-per-prompt "$PAM_SERVICE_NAME" "$user" authenticate \
        < "$fifo" > "$out" 2> "$err" &
    local driver=$!
    DRIVER_PID="$driver"

    # `timeout` не даёт открытию FIFO повиснуть навсегда, если драйвер успел
    # закончиться до записи: читателя у трубы тогда нет вовсе.
    timeout 15 sh -c 'printf "%s\n%s\n" "$1" "$2" > "$3"' sh \
        "$OPERATOR_ID" "$DEVICE_KEY_PIN" "$fifo" 2>/dev/null || true

    local rc=0
    wait "$driver" || rc=$?
    DRIVER_PID=""
    rm -f "$fifo"

    cat "$out"
    cat "$err" >&2
    return "$rc"
}

# Поток запросов challenge. Каждый разговор обрывается на напечатанном
# challenge — ровно то, что может сделать всякий, кто дотягивается до PAM-стека
# с именем ролевой учётной записи, не зная ни кода, ни билета.
#
# Проверяется не «отказали», а ЧЕМ отказали. Счётчик nonce устройства конечен и
# при исчерпании не восстанавливается без физического привоза новой эпохи ключа,
# поэтому единственный приемлемый исход потока — временный отказ в выдаче
# (PAM_MAXTRIES), после которого метод возвращается сам. Постоянный отказ
# (CounterExhausted) — тот самый худший исход, ради которого кейс и написан, и
# он тоже приходит кодом 11: различает их шаг восстановления, а не этот.
cmd_issue_storm() {
    local user="${1:-}" level="" count="" recover_after=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            --count)
                count="${2:-}"
                shift 2 || usage_error "--count без значения"
                ;;
            --recover-after)
                recover_after="${2:-}"
                shift 2 || usage_error "--recover-after без значения"
                ;;
            *) usage_error "неизвестный аргумент issue-storm: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] && [ -n "$count" ] \
        || usage_error "usage: codes-phone.sh issue-storm <user> --level N --count M [--recover-after S]"

    load_prepared

    local i
    for ((i = 0; i < count; i++)); do
        # Обрыв разговора — ожидаемый исход этого шага, а не сбой: код возврата
        # драйвера здесь не вердикт продукта. Отказ в выдаче тоже обрывает
        # разговор, и это нормально — поток на то и поток.
        capture_challenge "$user" 2>/dev/null || true
    done
    echo "storm: $count challenge(s) requested"

    if [ -n "$recover_after" ]; then
        # Запор обязан отпустить сам. Ожидание идёт по настенным часам стенда:
        # устройство меряет его по монотонным маркерам, и совпадение этих двух
        # шкал в пределах прогона — единственное, на что кейс здесь опирается.
        sleep "$recover_after"
        run_conversation "$user" "$level" issue 1
        return
    fi

    run_conversation "$user" "$level" issue 1
}

cmd_revoke_ticket() {
    load_prepared
    require_root
    # Список отзыва — одна строка на номер билета, тем же порядком, что CRL:
    # он применяется до аутентификации, поэтому дописать его достаточно.
    printf '%s\n' "$TICKET_NUMBER" >> "$CODES_DIR/tickets.revoked"
    chmod 0644 "$CODES_DIR/tickets.revoked"
    echo "revoked: $TICKET_NUMBER"
}

# ----------------------------------------------------------------------------
# cleanup
# ----------------------------------------------------------------------------

# Идемпотентен и не опирается на prepare: teardown кейса выполняется при любом
# исходе, включая падение подготовки на середине.
cmd_cleanup() {
    [ "$(id -u)" = "0" ] || die "требуются права root"

    if [ -f "$CONFIG_BACKUP" ]; then
        local staging="$CONFIG.e2e-codes"
        cp "$CONFIG_BACKUP" "$staging"
        if [ -f "$CONFIG" ]; then
            chmod --reference="$CONFIG" "$staging"
            chown --reference="$CONFIG" "$staging"
        fi
        mv -f "$staging" "$CONFIG"
        rm -f "$CONFIG_BACKUP"
    fi

    rm -f "$PAM_SERVICE"

    # Убирается только то, что разложил prepare, а сам каталог — лишь если после
    # этого он пуст: устройство парка могло получить артефакты не от прогона.
    rm -f "$CODES_DIR/device.p12" "$CODES_DIR/tickets.txt" \
        "$CODES_DIR/tickets.revoked" "$CODES_DIR/ticket-authority.pem"
    rm -rf "$STATE_DIR"
    rmdir "$CODES_DIR" 2>/dev/null || true

    rm -rf "$RUN_DIR"

    echo "cleaned"
}

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        prepare)              cmd_prepare "$@" ;;
        authenticate)         cmd_authenticate "$@" ;;
        authenticate-with-code) cmd_authenticate_with_code "$@" ;;
        expect-issue-refused) cmd_expect_issue_refused "$@" ;;
        exhaust-attempts)     cmd_exhaust_attempts "$@" ;;
        replay-after-restart) cmd_replay_after_restart "$@" ;;
        snapshot-counter)     cmd_snapshot_counter "$@" ;;
        restore-counter)      cmd_restore_counter "$@" ;;
        authenticate-without-code) cmd_authenticate_without_code "$@" ;;
        issue-storm)          cmd_issue_storm "$@" ;;
        revoke-ticket)        cmd_revoke_ticket "$@" ;;
        cleanup)              cmd_cleanup "$@" ;;
        -h|--help)            usage; exit 0 ;;
        "")                   usage; exit "$EXIT_USAGE" ;;
        *)                    usage_error "неизвестная команда: $cmd" ;;
    esac
}

main "$@"
