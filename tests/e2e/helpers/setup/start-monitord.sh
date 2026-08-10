#!/usr/bin/env bash
# start-monitord.sh — поднимает демон наблюдения в контейнерном окружении.
#
# Штатный юнит требует системной шины D-Bus: без неё демон отказывается
# стартовать, потому что действия над сессией (блокировка, завершение) идут
# через logind. В контейнере шины нет, поэтому демон запускается с флагом
# `--no-dbus`, предназначенным ровно для таких проверок. Всё, что делается
# через logind, при этом недоступно — кейсы, зависящие от него, должны идти
# на профиле с настоящей системой.
#
# Флаг добавляется drop-in'ом к штатному юниту, а не запуском бинаря мимо
# systemd: так демон остаётся службой, его вывод попадает в журнал под именем
# юнита, и кейсы могут смотреть журнал обычным образом.

set -euo pipefail

UNIT=tessera
DROPIN_DIR="/etc/systemd/system/${UNIT}.service.d"
DROPIN="${DROPIN_DIR}/e2e-no-dbus.conf"

command -v systemctl >/dev/null 2>&1 || {
    echo "start-monitord: systemctl не найден — профиль без менеджера служб" >&2
    exit 70
}

# Реестр сессий переживает перезапуск демона: он для того и лежит на диске.
# Для прогона это ловушка — сессия, открытая прошлым прогоном в том же
# контейнере, поднимается вместе с демоном, и кейс про извлечение носителя
# может увидеть её реакцию вместо своей. Прогон начинается с чистого реестра.
rm -f /run/tessera/sessions.json

mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<'EOF'
# Создаётся helpers/setup/start-monitord.sh для контейнерных прогонов.
[Service]
ExecStart=
ExecStart=/usr/bin/tessera daemon --config /etc/tessera/config.toml --no-dbus
EOF

systemctl daemon-reload
systemctl restart "$UNIT"

# Готовность — это принимающий сокет, а не «служба запущена»: кейсы обращаются
# к нему сразу, и гонка дала бы им ложный отказ.
for _ in $(seq 1 50); do
    if [ -S /run/tessera/monitord.sock ]; then
        echo "monitord: сокет принимает подключения"
        exit 0
    fi
    sleep 0.2
done

echo "start-monitord: сокет /run/tessera/monitord.sock не появился за 10 с" >&2
systemctl status "$UNIT" --no-pager 2>&1 | tail -5 >&2
exit 70
