# Design: issuer-release-binary

Новый workflow `release-issuer.yml` собирает `issuer` с встроенным кабинетом под
3 платформы и доливает в релиз тега. `build.yml` (`.deb`) не трогается.

## Топология job'ов

```
cabinet-dist (ubuntu, Node+Rust+wasm32) → build.sh → artifact: cabinet-dist
   │
build-issuer  (matrix, needs cabinet-dist)
   ├─ linux-x86_64  : container astra-builder ; download dist → cabinet/dist ;
   │                  cargo build --release -p tessera_issuer
   │                  --features cli,pkcs11,vault,serve,embed-cabinet
   ├─ macos-arm64   : macos-latest runner ; тот же build
   └─ windows-x86_64: windows-latest runner ; тот же build (issuer.exe)
   │  каждый → artifact: issuer-<target>
   │
release-issuer (needs build-issuer, if tag v*)
   download все issuer-* → SHA256SUMS → softprops/action-gh-release (draft,
   append к релизу тега)
```

**Почему dist собирается отдельно:** `cabinet/build.sh` требует Node+esbuild+wasm.
Собрать раз на ubuntu и раздать артефактом дешевле и надёжнее, чем ставить Node в
astra-контейнер и на каждый раннер. Каждая платформа только встраивает готовый
`dist` (`include_dir!` за `embed-cabinet`) — нужен лишь Rust.

**Почему Linux в astra-контейнере:** glibc обратно-совместим, не вперёд. Бинарь,
собранный против старого glibc astra-builder, работает на Astra и на новее
(Ubuntu/Debian). Тот же контейнер, что и `.deb` (`ghcr.io/tesseralabs/tessera-astra-builder`).

**Фичи релиз-бинаря:** `cli,pkcs11,vault,serve,embed-cabinet` — оба бэкенда
(токен/HSM + Vault Transit) + serve + кабинет. `native-tls` (vault) на
glibc/macOS/Windows линкуется штатно (musl не берём — там openssl не статится,
это отложенный musl-ассет без vault).

## Артефакты и целостность

- Имена: `issuer-linux-x86_64`, `issuer-macos-arm64`, `issuer-windows-x86_64.exe`.
- `SHA256SUMS` по всем бинарям — в релиз (целостность скачанного; сам кабинет
  внутри бинаря покрыт его целостностью).
- Draft-релиз — как `.deb` (владелец промоутит вручную).

## Границы

- `build.yml`/`.deb` и device-агент не трогаются.
- Версия/тег — тот же `v*`, что и `.deb` (release-issuer доливает в тот же релиз).
- musl-static Linux (любой дистрибутив, без vault) — отложено, отдельный ассет.
- Подпись бинарей (codesign/authenticode) — не в этот change (draft-релиз,
  внутренняя поставка); при необходимости позже.

## Проверка

- YAML-валидность; локальная release-сборка issuer со всеми фичами
  (`cargo build --release -p tessera_issuer --features cli,pkcs11,vault,serve,embed-cabinet`
  при собранном `cabinet/dist`) — компилируется на хосте-разработчике.
- Полный прогон workflow — на первом теге `v*` после мержа (или `workflow_dispatch`).
