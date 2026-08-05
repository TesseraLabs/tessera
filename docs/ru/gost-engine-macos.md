# Подключение GOST-движка для OpenSSL на macOS (Homebrew, arm64)

Готовой сборки под `openssl@3` в Homebrew нет — собирается из исходников
проекта [gost-engine](https://github.com/gost-engine/engine). Нужен
только для локального выпуска тестовых ГОСТ-сертификатов (§3–§4
[install.md](install.md)) на рабочей станции администратора; сам
`tessera` — Linux-only и на macOS не устанавливается.

## 1. Инструменты для сборки

```bash
brew install cmake
```

## 2. Клонировать движок

```bash
git clone --recurse-submodules https://github.com/gost-engine/engine.git gost-engine
cd gost-engine
```

## 3. Собрать под вашу версию OpenSSL

```bash
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
  -DOPENSSL_ENGINES_DIR=$(brew --prefix openssl@3)/lib/engines-3
cmake --build . -j"$(sysctl -n hw.ncpu)"
```

Движок — бинарный ABI-модуль, собирать нужно именно против той версии
OpenSSL, с которой будет работать. Если позже обновите `openssl@3` через
`brew` — пересоберите движок заново.

## 4. Установить в каталог engines

```bash
sudo cmake --install .
```

Если `OPENSSL_ENGINES_DIR` указан как выше, попадёт прямо в
`$(brew --prefix openssl@3)/lib/engines-3/gost.dylib`; `/opt/homebrew`
обычно пользовательский, `sudo` может не понадобиться.

Если install target не найден — скопировать вручную:

```bash
cp bin/gost.dylib $(brew --prefix openssl@3)/lib/engines-3/gost.dylib
```

## 5. Зарегистрировать движок в `openssl.cnf` (опционально)

Найти активный конфиг: `openssl version -d`. В `openssl.cnf` добавить:

```ini
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
dynamic_path = /opt/homebrew/Cellar/openssl@3/<version>/lib/engines-3/gost.dylib
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet
```

Без правки конфига движок всё равно грузится явно флагом `-engine gost`
в командах `openssl` — именно так он используется во всех примерах
[install.md](install.md).

## 6. Проверка

```bash
openssl engine -t -c gost
```

Ожидаемый вывод — список алгоритмов ГОСТ (`GOST94`, `GOST2001`,
`GOST28147`, …) и `[ available ]`.

## Не забывайте `-engine gost` явно

На macOS без правки `openssl.cnf` (шаг 5) движок не подключается
автоматически — каждая команда, читающая или проверяющая ГОСТ-ключ или
сертификат, требует явного `-engine gost`. В частности,
`openssl verify` без этого флага падает с
`X509_PUBKEY_get0:decode error` / `unable to get local issuer
certificate`, хотя ключ и сертификат совершенно корректны — движку
просто нечем декодировать ГОСТ-структуру публичного ключа. Правильная
форма:

```bash
openssl verify -engine gost -CAfile ca.pem ca.pem
```
