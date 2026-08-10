# Профиль ubuntu-container: контейнер с настоящим systemd как PID 1.
#
# Образ намеренно тонкий: rust-toolchain и dev-заголовки продукта сюда не входят.
# Прогоняется тот .deb, что уезжает на машины, в среде, похожей на машину; сборкой
# занимается docker/astra-builder.Dockerfile, который в прогоне не участвует.
# Компилятор в образе есть только ради pam-drive — драйвера PAM-фаз, который
# собирается здесь же и остаётся в образе бинарём.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# systemd/systemd-sysv — менеджер служб профиля; udev — обнаружение носителя;
# dosfstools — mkfs.vfat для эмулированного носителя; libpam* — рантайм PAM,
# который тянет за собой и pam_tessera из .deb.
#
# Остальное закрывает поле Depends проверяемого пакета: пакет обязан вставать
# одним `dpkg -i`, без доустановки зависимостей из сети. adduser нужен postinst
# для системной учётной записи демона, libssl3t64 — рантайм OpenSSL (в noble
# именно он объявляет Provides: libssl3). libc6, libgcc-s1, init-system-helpers
# и lsb-base (последний через Provides в sysvinit-utils) уже есть в базовом
# образе, libpam0g и libudev1 перечислены выше.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        udev \
        dosfstools \
        kmod \
        libpam0g \
        libpam-modules \
        libudev1 \
        libssl3t64 \
        adduser \
        ca-certificates \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Сборка pam-drive: gcc и заголовки PAM нужны только на этом шаге и удаляются
# следом, чтобы образ не превратился в сборочный.
COPY helpers/pam-drive.c /usr/local/src/pam-drive.c
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libpam0g-dev \
    && gcc -O2 -Wall -Wextra -o /usr/local/bin/pam-drive /usr/local/src/pam-drive.c -lpam \
    && apt-get purge -y gcc libc6-dev libpam0g-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /usr/local/src/pam-drive.c

# Под эмуляцией x86_64 на arm-хосте (Rosetta) транслятору нужна память,
# одновременно записываемая и исполняемая, а systemd закрывает её у своих
# юнитов через MemoryDenyWriteExecute — udevd и journald при старте получают
# SIGTRAP и служба остаётся failed. Послабление касается только этих двух
# служб тестового образа; юниты продукта не трогаются, и на нативном amd64
# drop-in ничего не меняет.
RUN mkdir -p /etc/systemd/system/systemd-udevd.service.d \
             /etc/systemd/system/systemd-journald.service.d \
    && printf '[Service]\nMemoryDenyWriteExecute=no\n' \
        | tee /etc/systemd/system/systemd-udevd.service.d/e2e-emulation.conf \
              /etc/systemd/system/systemd-journald.service.d/e2e-emulation.conf >/dev/null

COPY helpers/usb-loop.sh helpers/ocsp-responder.sh helpers/udevd-start.sh \
     helpers/config-mutate.sh /opt/tessera-e2e/helpers/
COPY helpers/setup/ /opt/tessera-e2e/helpers/setup/
RUN chmod 0755 /opt/tessera-e2e/helpers/*.sh /opt/tessera-e2e/helpers/setup/*.sh \
    && mkdir -p /opt/tessera-e2e/fixtures /opt/tessera-e2e/pkg

# Раннер выполняет подготовку suite как `helpers/setup/<name>.sh` — путь
# относительный, поэтому рабочий каталог должен быть корнем раскладки хелперов.
WORKDIR /opt/tessera-e2e

# Штатный сигнал завершения systemd: SIGTERM он трактует иначе и контейнер
# останавливается по таймауту.
STOPSIGNAL SIGRTMIN+3

# Запуск профиля (см. tests/e2e/profiles/ubuntu-container.toml):
#   docker run -d --privileged --cgroupns=host \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock <image>
# Готовность: systemctl is-system-running ∈ {running, degraded}.
CMD ["/sbin/init"]
