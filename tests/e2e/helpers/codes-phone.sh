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
#   codes-phone.sh authenticate-with-device-key <user> --level N
#   codes-phone.sh expect-issue-refused-under-another-name <user> --level N
#   codes-phone.sh expect-issue-refused <user> --level N
#   codes-phone.sh exhaust-attempts <user>
#   codes-phone.sh replay-in-new-conversation <user>
#   codes-phone.sh replay-after-restart <user>
#   codes-phone.sh authenticate-without-code <user>
#   codes-phone.sh revoke-ticket
#   codes-phone.sh cleanup
#
# Разговор состоит из четырёх ответов подряд («Оператор: », «Личный номер: », PIN
# контейнера, «Код: »), и последний вычисляется по тому, что модуль напечатал перед
# промптом кода. Поэтому
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
# Каталог квитанций выдачи.
#
# Каталог и состояние устройства обнуляются ОДНОВРЕМЕННО, подкомандой prepare.
# Счётчика выдач, который когда-то связывал эти два хранилища, больше нет — ни
# на устройстве, ни у выдачи, — но связка нужна по-прежнему, по другой причине:
# сверка (`issuer codes reconcile`, сюита 31) сопоставляет квитанции с журналом
# устройства, и половина от прошлого прогона рядом со свежей половиной даёт
# находки, которых на приборе не было. Очистка идёт каталогом целиком, поэтому
# добавленное в него завтра попадёт под неё тоже.
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

# Личный номер инженера, которым хелпер представляется на промпте «Личный номер: ».
# Сверять его не с чем: реестра людей на офлайн-устройстве нет, — но в байты кода
# он входит, поэтому значение обязано быть ОДНО на обе стороны: устройство берёт
# его из ответа на промпт, выдача — из challenge, куда его положило устройство.
# В device.env не вынесен намеренно: фикстуры о нём ничего не знают и знать не
# должны, иначе комплект пришлось бы пересобирать ради строки.
ENGINEER_ID="${TESSERA_E2E_ENGINEER_ID:-eng-1}"

# Личный номер ДРУГОГО инженера — того, кому код не выдавался. Используется
# только режимом authenticate-under-another-name.
OTHER_ENGINEER_ID="${TESSERA_E2E_OTHER_ENGINEER_ID:-eng-2}"

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
  authenticate-mistyping-once <user> --level N
                        вход, где первый код набран неверно, а второй верно:
                        журнал устройства получает отказ и успех на ОДИН nonce
  authenticate-with-code <user> --level N --code <код>
                        то же, но код задан снаружи и подаётся как есть;
                        выдача не вызывается вовсе
  authenticate-with-device-key <user> --level N
                        код считается по ПРЕЖНЕЙ схеме — из статического ключа
                        устройства, без участия эфемерной пары попытки;
                        подменённый challenge подписывается тем же ключом
                        устройства (у снявшего диск он есть), ожидается отказ
                        сверки на устройстве
  expect-issue-refused-under-another-name <user> --level N
                        выдаче называют ЧУЖОЙ личный номер инженера;
                        0 только на отказ по подписи устройства
  expect-issue-refused <user> --level N
                        проверить, что выдача НЕ считает код на уровень вне
                        рамок билета; 0 только на отказ по рамкам
  exhaust-attempts <user>
                        исчерпать бюджет попыток ввода кода в одном прогоне
  replay-in-new-conversation <user>
                        успешный вход, затем тот же код во втором разговоре —
                        без перезапуска
  replay-after-restart <user>
                        успешный вход, перезапуск устройства, тот же код снова
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
#   OWNER_ID=...        идентификатор владельца, заверившего запись третьей
#                       подписью. Передаётся выдаче тем же флагом: владелец —
#                       такой же именованный подписант, отличает их сообщение,
#                       а не механизм якорей.
#
# Сторона устройства (кладётся в `[codes].dir` подкомандой prepare):
#
#   device.p12             PKCS#12 с ПРИВАТНЫМ ключом устройства той эпохи, что
#                          в EPOCH, под PIN из DEVICE_KEY_PIN. Профиль ключа —
#                          p256 (умолчание `[codes].profile`); из контейнера
#                          берётся только ключ.
#   tickets.txt            действующие билеты операторов, по одному документу
#                          контракта в строке — строка вида
#                          `tessera-codes/v1/ticket;server=...;key=<hex SEC1>;
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
#   owner-anchor.pem       SubjectPublicKeyInfo (PEM или DER) владельца OWNER_ID —
#                          им проверяется третья подпись записи устройства.
#   device-record.txt      запись устройства, одна строка вида
#                          `tessera-codes/v1/device-record;device=<номер с
#                          контрольным символом>;key=<hex SEC1 открытого ключа
#                          устройства>;epoch=<u32>;organisation=<ORGANISATION_ID>;
#                          serials=<вид:номер,…>;key_protection=<ступень>;
#                          anchor=<none|tpm|carrier>;batch=…;baseline=<hex>;
#                          organisation=…;owner=…;possession_signature=<hex DER>;
#                          organisation_signature=<hex DER>;
#                          owner_signature=<hex DER>`. ТРИ подписи в том порядке,
#                          в котором их ставят: PoP ключом устройства по телу,
#                          организация — по телу вместе с PoP, владелец — по
#                          digest всего предыдущего. Порядок — свойство формата:
#                          переставленные подписи не разбираются и не сходятся.
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
    ORGANISATION_ID OWNER_ID)

DEVICE_FILES=(device.p12 tickets.txt ticket-authority.pem)
OPERATOR_FILES=(operator-ticket.txt operator-key.pem device-record.txt organisation-anchor.pem
    owner-anchor.pem)

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
        printf 'OWNER_ID=%q\n' "$OWNER_ID"
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
    # Квитанции обнуляются вместе с состоянием устройства — см.
    # deploy_artefacts. Счётчиков, которые когда-то обязаны были идти в ногу,
    # нет ни на одной стороне; связка осталась ради сверки, которая
    # сопоставляет квитанции с журналом устройства и на разъехавшихся половинах
    # находит то, чего на приборе не было.
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

# Устройство печатает challenge полями через « / »: номер, эпоха, nonce, роль,
# уровень, оператор, личный номер инженера, эфемерная точка попытки и подпись
# устройства. Номер и nonce разбиты на группы по три символа, потому что длинный
# прогон цифр человек перевирает; точка и подпись идут одним прогоном
# шестнадцатеричного — их не диктуют, их переносят. Выдача набирает у себя ровно
# то, что получила; здесь набор и происходит: пробелы внутри групп убираются,
# поля раскладываются по ключам проводной формы контракта в её единственном
# порядке.
#
# ВАЖНО про перебивку полей ниже: подпись устройства покрывает все восемь полей,
# поэтому challenge с перебитым полем выдача отвергает по подписи. Своей подписи
# у хелпера нет и быть не может — канонические байты сообщения собирает крейт
# контракта, а второе их написание на языке оболочки разошлось бы с первым
# молча. Перебивка поэтому годится ровно там, где проверяется отказ, наступающий
# РАНЬШЕ проверки подписи (рамки билета), или сам отказ по подписи.
#
# Второй аргумент — уровень, которым перебивается полученное поле. Он нужен
# ровно одному кейсу: проверке, что выдача не считает код за пределами рамок
# билета. Метку процесса на системе без мандатного механизма не поднять, а для
# выдачи challenge — это строка, которую ей передали, и рамки она проверяет
# по ней. Подмена уровня здесь и есть проверяемый ввод; на устройство этот
# challenge не возвращается.
#
# Третий — эфемерная точка, которой перебивается полученная. Нужен кейсу про
# код, посчитанный из одного статического ключа устройства (см. run_conversation,
# источник device-key).
#
# Четвёртый — личный номер инженера, которым перебивается полученный. Нужен кейсу
# про код под чужим именем (источник other-name): устройство ждёт код на номер,
# который ему назвали на промпте, а выдаче называют другой.
wire_from_spoken() {
    local spoken="$1" level_override="${2:-}" ephemeral_override="${3:-}" \
        engineer_override="${4:-}"
    local IFS='/'
    # shellcheck disable=SC2206  # разбиение по разделителю полей — здесь оно и нужно
    local fields=($spoken)
    [ "${#fields[@]}" -eq 9 ] || die "challenge не разобрался в девять полей: $spoken"
    local trimmed=() field
    for field in "${fields[@]}"; do
        # Пробелы группировки и обрамления снимаются целиком; внутри значений
        # контракта пробела быть не может — проводная форма его не несёт.
        trimmed+=("$(printf '%s' "$field" | tr -d '[:space:]')")
    done
    [ -z "$level_override" ] || trimmed[4]="$level_override"
    [ -z "$engineer_override" ] || trimmed[6]="$engineer_override"
    [ -z "$ephemeral_override" ] || trimmed[7]="$ephemeral_override"
    printf 'tessera-codes/v1/signed-challenge;device=%s;epoch=%s;nonce=%s;role=%s;level=%s;server=%s;engineer=%s;ephemeral=%s;signature=%s' \
        "${trimmed[0]}" "${trimmed[1]}" "${trimmed[2]}" \
        "${trimmed[3]}" "${trimmed[4]}" "${trimmed[5]}" \
        "${trimmed[6]}" "${trimmed[7]}" "${trimmed[8]}"
}

# Инструмент стенда, подписывающий challenge ключом устройства.
#
# Зовётся ровно в одном месте: там, где моделируется снятый диск и подменённый
# challenge надо подписать так, как подписал бы атакующий с ключом на руках.
# Своей подписи у хелпера нет и быть не может — канонические байты сообщения
# собирает крейт контракта, а второе их написание на языке оболочки разошлось бы
# с первым молча, и кейс проверял бы сходство двух написаний.
#
# Бинарь доставляет раннер, как и `issuer`: секция `[[artifacts]]` в stand.toml.
# Отсутствие инструмента — сбой стенда, а не отказ продукта, и говорится об этом
# именно так.
SIGN_TOOL="${TESSERA_E2E_XTASK:-tessera-xtask}"

sign_challenge() {
    local signed="$1"
    command -v "$SIGN_TOOL" >/dev/null 2>&1 || die \
        "не найден $SIGN_TOOL — подписать подменённый challenge нечем; бинарь доставляет раннер ([[artifacts]] в stand.toml)"

    # Инструмент подписывает НЕподписанную форму, а у хелпера на руках
    # подписанная: снимается хвост с подписью и возвращается исходный префикс.
    # Порядок и написание полей при этом не повторяются нигде — строку собрал
    # wire_from_spoken, здесь у неё только отрезан хвост.
    local unsigned="${signed%;signature=*}"
    unsigned="tessera-codes/v1/challenge${unsigned#tessera-codes/v1/signed-challenge}"

    "$SIGN_TOOL" codes-sign-challenge \
        --challenge "$unsigned" \
        --key "$FIXTURES_CODES_DIR/device-key.pem" \
        || die "$SIGN_TOOL не подписал challenge"
}

# Открытая половина СТАТИЧЕСКОГО ключа устройства — та, что записана в реестре
# устройства (`key=` в device-record.txt). Именно её знает всякий, кто снял с
# устройства диск: приватную половину он берёт из device.p12.
device_static_point() {
    local record="$FIXTURES_CODES_DIR/device-record.txt"
    local point
    point="$(sed -n 's/.*;key=\([0-9a-fA-F]*\);.*/\1/p' "$record")"
    [ -n "$point" ] || die "в $record не нашлось поля key= с открытым ключом устройства"
    printf '%s' "$point"
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
        --anchor-organisation "$OWNER_ID=$FIXTURES_CODES_DIR/owner-anchor.pem" \
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
# оператора), `device-key` (посчитать по прежней схеме, из статического ключа
# устройства), `other-name` (посчитать на чужой личный номер), `wrong`
# (заведомо неверный), либо `fixed:<код>`; $4 — сколько раз отвечать на промпт
# кода.
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
    printf '%s\n' "$ENGINEER_ID" >&3
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
        device-key)
            # Код по ПРЕЖНЕЙ схеме: из статического ключа устройства, без
            # эфемерной пары попытки. Именно его считает тот, у кого на руках
            # содержимое диска и билет, — и больше ничего.
            #
            # Своей формулы у хелпера по-прежнему нет: считает всё та же
            # `issuer codes issue`, ей лишь подменяется эфемерная точка на
            # открытую половину статического ключа устройства. Обмен ключами
            # симметричен, поэтому выдача своим ключом против статической точки
            # приходит ровно к тому `Z`, к которому атакующий приходит
            # статическим ключом устройства против ключа билета.
            #
            # Подменённая строка ПОДПИСЫВАЕТСЯ ЗАНОВО ключом устройства, и это
            # не поблажка стенду: у моделируемого атакующего ключ есть по
            # условию задачи — он снял диск. Кейс, где отказ приходил бы по
            # подписи, проверял бы не ту гарантию: настоящий атакующий этого
            # класса подписал бы законно. Отказ обязан прийти из сверки кода.
            #
            # Подписывает инструмент стенда — теми же байтами, что и продукт,
            # через тот же крейт контракта (см. sign_challenge).
            local spoken
            spoken="$(await_challenge "$err" "$driver")"
            code="$(issue_code "$(sign_challenge \
                "$(wire_from_spoken "$spoken" "" "$(device_static_point)")")")"
            [ -n "$code" ] || die "выдача не вернула код (см. $err)"
            printf '%s\n' "$code" > "$RUN_DIR/last-code"
            ;;
        other-name)
            die "режим other-name недоступен: подмена личного номера ломает подпись устройства, и проверяется теперь отказом выдачи — см. expect-issue-refused-under-another-name"
            ;;
        wrong) code="$WRONG_CODE" ;;
        mistyped-then-right)
            # Инженер ошибся в коде и со второго раза ввёл верный — самая
            # обычная вещь, ради которой у nonce и есть бюджет попыток.
            # Устройство пишет в свою цепочку ДВЕ строки на один nonce: отказ и
            # успех. Кейс сверки живёт именно на этом журнале.
            local spoken
            spoken="$(await_challenge "$err" "$driver")"
            code="$(issue_code "$(wire_from_spoken "$spoken")")"
            [ -n "$code" ] || die "выдача не вернула код (см. $err)"
            printf '%s\n' "$code" > "$RUN_DIR/last-code"
            printf '%s\n' "$WRONG_CODE" >&3
            # Первый ответ уже подан; остальные — верный код.
            code_answers=$((code_answers - 1))
            ;;
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
    printf '%s\n' "$ENGINEER_ID" >&3
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
# PAM_TEXT_INFO, следом за строкой «Передайте выдающей стороне:», и содержит восемь
# полей через « / » (седьмое — личный номер инженера, восьмое — эфемерная точка
# попытки). Ожидание ограничено:
# разговор, застрявший до промпта кода, обязан кончиться диагностикой, а не
# висеть до таймаута кейса.
await_challenge() {
    local err="$1" driver="$2" waited=0
    local limit="${TESSERA_E2E_CHALLENGE_TIMEOUT:-30}"
    while :; do
        local line
        line="$(grep -m1 -E ' / .* / .* / .* / .* / .* / .* / ' "$err" 2>/dev/null || true)"
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

# Вход, в котором инженер ошибается кодом один раз и вводит верный со второго.
#
# Нужен сверке: журнал устройства получает на один nonce две строки, отказ и
# успех. Сверка обязана прочитать это как один вход, а не как два, — иначе
# опечатка на клавиатуре поднимает класс находки, документированный как «прибор
# не тот, за который себя выдаёт».
cmd_authenticate_mistyping_once() {
    local user="${1:-}" level=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент authenticate-mistyping-once: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] \
        || usage_error "usage: codes-phone.sh authenticate-mistyping-once <user> --level N"

    load_prepared
    run_conversation "$user" "$level" mistyped-then-right "$ATTEMPTS_PER_NONCE"
}

# Вход кодом, посчитанным из одного статического ключа устройства.
#
# Моделируется изъятие носителя: подготовитель снял диск, восстановлен бэкап,
# устройство украдено. Атакующему доступно всё, что лежит на устройстве, ключ
# устройства включительно, — но не приватная половина эфемерной пары попытки: на
# момент снятия образа её не существует. Устройство обязано отказать сверкой
# кода — и именно сверкой: подменённый challenge подписывается тем же ключом
# устройства, поэтому выдача проходит и до сверки дело доходит.
#
# Код подаётся на весь бюджет попыток, как и в authenticate-with-code, и по той
# же причине: цикл переспроса живёт в модуле, а одна строка оборвала бы разговор
# на втором промпте ошибкой драйвера.
cmd_authenticate_with_device_key() {
    local user="${1:-}" level=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент authenticate-with-device-key: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] \
        || usage_error "usage: codes-phone.sh authenticate-with-device-key <user> --level N"

    load_prepared
    run_conversation "$user" "$level" device-key "$ATTEMPTS_PER_NONCE"
}

# Выдача под чужим личным номером: у устройства стоит один инженер и называет
# свой номер, а выдаче называют номер другого.
#
# Проверяется отказ ВЫДАЧИ, а не сверка на устройстве. Личный номер стоит в
# подписанном challenge, подпись устройства покрывает его, и подменивший номер
# не может подписать заново — ключа устройства у него нет. Поэтому разговор до
# ввода кода не доходит вовсе: выдача не считает ничего.
#
# То, что номер входит и в БАЙТЫ кода — гарантия отдельная и живая; её держат
# юнит-тесты ядра, где код на чужой номер считается настоящей формулой и не
# сходится. Здесь снаружи наблюдается более ранний рубеж.
#
# Ноль возвращается ТОЛЬКО на отказ по подписи. Выданный код — провал гарантии;
# отказ по любой другой причине — сбой стенда.
cmd_expect_issue_refused_under_another_name() {
    local user="${1:-}" level=""
    shift || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --level)
                level="${2:-}"
                shift 2 || usage_error "--level без значения"
                ;;
            *) usage_error "неизвестный аргумент expect-issue-refused-under-another-name: $1" ;;
        esac
    done
    [ -n "$user" ] && [ -n "$level" ] \
        || usage_error \
            "usage: codes-phone.sh expect-issue-refused-under-another-name <user> --level N"

    load_prepared
    capture_challenge "$user"

    local wire
    wire="$(wire_from_spoken "$(cat "$CHALLENGE_FILE")" "" "" "$OTHER_ENGINEER_ID")"

    local err="$RUN_DIR/issue.err" rc=0
    run_issue "$err" "$wire" > /dev/null || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "codes-phone: выдача посчитала код на чужой личный номер $OTHER_ENGINEER_ID" >&2
        return 1
    fi

    local class outcome
    class="$(issue_refusal_class "$err")"
    outcome="$(issue_outcome "$rc")"
    if [ "$outcome" = tool ]; then
        cat "$err" >&2
        die "выдача не дошла до ответа ($class, код $rc) — сбой стенда, а не проверенная гарантия"
    fi
    case "$class" in
        challenge_signature_rejected)
            [ "$rc" = "$ISSUE_EXIT_TRUST" ] || die \
                "класс отказа $class, а код возврата $rc вместо $ISSUE_EXIT_TRUST — выдача противоречит сама себе"
            echo "выдача отказала по подписи устройства: $class"
            return 0
            ;;
        *)
            cat "$err" >&2
            die "выдача отказала классом $class — это не отказ по подписи, гарантия не проверена"
            ;;
    esac
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
#   12 не сошлись подписи или доверие, включая подпись устройства на challenge
#   13 выдача без основания
#   14 прочий отказ выдачи, включая неразобравшийся challenge
#   1  ПРОВЕРКА НЕ СОСТОЯЛАСЬ — нет файла, документ не разобрался, ключ недоступен
#
# Кода 11 в таблице нет: он был у отказа «счётчик не сходится с историей выдач»,
# а счётчика выдач не существует — вместе с ним ушёл и реестр `ledger.ndjson`,
# который тут когда-то назывался. Инженер, разбирающий упавший прогон, искал бы
# файл, которого на стенде нет.
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
ISSUE_EXIT_TRUST=12

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
# /run пропадает. Файла потреблённых nonce, который когда-то обязан был это
# пережить, нет — попытка живёт в памяти процесса и кончается вместе с ним, — а
# пережить рестарт обязан троттл: бюджет выдач и счёт неудач лежат в файле
# состояния, и перезапуск службы не имеет права их обнулять.
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

# Тот же код во ВТОРОМ разговоре, без всякого перезапуска.
#
# Попытка, чей код приняли, кончилась вместе с ответом; следующий разговор
# заводит новую попытку с новым nonce, и код от прошлой не сходится по MAC. На
# устройстве не осталось ни файла потреблённых nonce, ни счётчика — гарантию
# держит то, что живой попытки с прежним nonce больше нет.
cmd_replay_in_new_conversation() {
    local user="${1:-}"
    [ -n "$user" ] || usage_error "usage: codes-phone.sh replay-in-new-conversation <user>"
    load_prepared

    local level
    level="$(current_level)"
    run_conversation "$user" "$level" issue 1 \
        || die "первый вход по коду не прошёл — повторять нечего"

    local code
    code="$(cat "$RUN_DIR/last-code")"
    [ -n "$code" ] || die "код первого входа не сохранился"

    # Код повторяется на весь бюджет попыток по той же причине, что в
    # authenticate-with-code: цикл переспроса живёт в модуле.
    run_conversation "$user" "$level" "fixed:$code" "$ATTEMPTS_PER_NONCE"
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
# Разговор без кода
# ----------------------------------------------------------------------------
#
# Устройство обязано отказать раньше, чем спросит код. Разговор обрывается на
# промпте, и это ожидаемый исход: кейс читает код возврата драйвера как есть.
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
    timeout 15 sh -c 'printf "%s\n%s\n%s\n" "$1" "$2" "$3" > "$4"' sh \
        "$OPERATOR_ID" "$ENGINEER_ID" "$DEVICE_KEY_PIN" "$fifo" 2>/dev/null || true

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
        authenticate-mistyping-once) cmd_authenticate_mistyping_once "$@" ;;
        authenticate-with-device-key) cmd_authenticate_with_device_key "$@" ;;
        expect-issue-refused-under-another-name) cmd_expect_issue_refused_under_another_name "$@" ;;
        expect-issue-refused) cmd_expect_issue_refused "$@" ;;
        exhaust-attempts)     cmd_exhaust_attempts "$@" ;;
        replay-in-new-conversation) cmd_replay_in_new_conversation "$@" ;;
        replay-after-restart) cmd_replay_after_restart "$@" ;;
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
