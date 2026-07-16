# Proposal: issuer-release-binary

## Why

После разворота [[tessera-issuer-tooling-impl]] (issuer-local-cabinet) кабинет
выпуска раздаётся самим бинарём `issuer serve` (кабинет встроен фичей
`embed-cabinet`). Бинарь стал способом доставки кабинета операторам — но CI его
как релиз **не собирает**: `build.yml` публикует только `.deb` агента enforcement
(pam + daemon), а спека `build-release` прямо исключает CA-инструменты из открытой
поставки. В результате оператор не может скачать готовый `issuer` — только собрать
сам (`cabinet/build.sh` → `cargo build --release --features embed-cabinet`).

Исключение CA-инструментов из спеки — артефакт эпохи до открытия issuer-tooling
(код `issuer` уже в публичном репо). Раз бинарь — способ доставки кабинета,
публикуем его открыто.

## What Changes

- **MODIFIED** требование `Release job` спеки `build-release`: на тегах `v*`
  публиковать в тот же draft GitHub Release, помимо `.deb` агента, **бинарь
  `issuer` с встроенным кабинетом** под Linux/macOS/Windows + `SHA256SUMS`.
  Снять исключение «CA-инструменты в открытую поставку не входят».
- **Новый workflow** `release-issuer.yml` (тег `v*` / `workflow_dispatch`):
  - job `cabinet-dist` — один раз собирает `cabinet/dist` (`build.sh`, нужен
    Node+wasm), выкладывает артефактом (чтобы платформам не тянуть Node);
  - matrix `build-issuer` — качает `dist`, встраивает и собирает
    `cargo build --release -p tessera_issuer --features cli,pkcs11,vault,serve,embed-cabinet`:
    - **Linux x86_64** — в контейнере `astra-builder` (самый старый glibc среди
      целей → бинарь работает на Astra, Ubuntu, Debian по обратной совместимости
      glibc);
    - **macOS** (arm64) и **Windows** (x86_64) — нативные раннеры;
  - job `release-issuer` — собирает бинари, считает `SHA256SUMS`, доливает в
    релиз тега (`softprops/action-gh-release`, draft — как `.deb`).
- Целостность: встроенный кабинет покрыт целостностью подписанного бинаря +
  `SHA256SUMS` в релизе.

Отложено: musl-static Linux-бинарь для «любого» дистрибутива (без Vault —
native-tls не статится); отдельный ассет позже при необходимости.

## Impact

- Спека `build-release`: 1 MODIFIED требование (`Release job`).
- CI: новый `.github/workflows/release-issuer.yml`; `build.yml`/`.deb` не
  трогаются (issuer в `.deb` не входит — device-сторона отдельна).
- Дистрибуция: `issuer`-бинарь становится открытым релиз-ассетом (3 платформы).
  Это меняет позицию спеки — согласовано (код уже открыт, бинарь = доставка
  кабинета).
