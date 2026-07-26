# Профиль astra-container: Astra Linux SE 1.8.5 без своего менеджера служб.
#
# Astra-шный /sbin/init намеренно завершается в контейнере — «init: parsec module
# missing, terminating to prevent data leakage», — потому что модуля ядра parsec
# здесь нет и быть не может. Эта защита не обходится: контейнер запускается с
# `sleep infinity`, а единственный нужный демон (udevd) поднимает helpers/udevd-start.sh.
# Следствие: MAC-кейсы (МКЦ, МРД, ЗПС) в этом профиле не исполняются — их место
# в профиле astra-vm.
#
# Образ amd64: собирать и запускать с `--platform linux/amd64` (на arm-Mac — через Rosetta).
FROM registry.astralinux.ru/astra/ubi18-systemd:1.8.5

ENV DEBIAN_FRONTEND=noninteractive

# Репозитории Astra доступны прямо из образа (frozen 1.8_x86-64/1.8.5).
# parsec-base — userspace-часть parsec: она есть в контейнере и нужна утилитам,
# модуль ядра ею не подменяется. pamtester в репозиториях Astra отсутствует —
# поэтому PAM-фазы гоняет собственный pam-drive.
#
# Поле Depends проверяемого пакета здесь закрыто базовым образом целиком
# (libc6, libgcc-s1, libpam0g, libssl3, libudev1, init-system-helpers,
# lsb-base, adduser) — в отличие от ubuntu, доустанавливать нечего.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        udev \
        dosfstools \
        parsec-base \
        ca-certificates \
        openssl \
    && rm -rf /var/lib/apt/lists/*

COPY helpers/pam-drive.c /usr/local/src/pam-drive.c
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libpam0g-dev \
    && gcc -O2 -Wall -Wextra -o /usr/local/bin/pam-drive /usr/local/src/pam-drive.c -lpam \
    && apt-get purge -y gcc libc6-dev libpam0g-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /usr/local/src/pam-drive.c

COPY helpers/usb-loop.sh helpers/ocsp-responder.sh helpers/udevd-start.sh /opt/tessera-e2e/helpers/
COPY helpers/setup/ /opt/tessera-e2e/helpers/setup/
RUN chmod 0755 /opt/tessera-e2e/helpers/*.sh /opt/tessera-e2e/helpers/setup/*.sh \
    && mkdir -p /opt/tessera-e2e/fixtures /opt/tessera-e2e/pkg

# Раннер выполняет подготовку suite как `helpers/setup/<name>.sh` — путь
# относительный, поэтому рабочий каталог должен быть корнем раскладки хелперов.
WORKDIR /opt/tessera-e2e

# Запуск профиля (см. tests/e2e/profiles/astra-container.toml):
#   docker run -d --platform linux/amd64 --privileged --cgroupns=host \
#     --tmpfs /run --tmpfs /run/lock <image> sleep infinity
# После старта — /opt/tessera-e2e/helpers/udevd-start.sh.
CMD ["sleep", "infinity"]
