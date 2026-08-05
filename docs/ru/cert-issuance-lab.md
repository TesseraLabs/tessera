# Выпуск тестового CA и удостоверения (ECDSA P-256)

> Тестовый CA и всё, что здесь описано, пригодно только для
> лабораторного развёртывания. Для production используется внешний
> УЦ — см. [docs/operations.md](operations.md).

Всё ниже — обычные вызовы `openssl`, без какого-либо движка: ECDSA
P-256 поддерживается встроенным `default`-provider'ом OpenSSL 3.x на
любой системе, включая macOS (и системный OpenSSL/LibreSSL, и
Homebrew) — ни `-engine`, ни отдельная сборка не нужны. Поэтому шаги
не обязаны выполняться на целевой Astra-машине — удобнее гонять их на
рабочей станции администратора.

## Создание тестового CA

### 1. Каталог

```bash
mkdir -p /tmp/ca && cd /tmp/ca
```

### 2. Ключ CA

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
chmod 0600 ca.key
```

### 3. Сертификат CA

```bash
openssl req -new -x509 -key ca.key \
    -out ca.pem -days 3650 \
    -subj "/CN=tessera Test CA/O=Test/OU=Internal" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### Проверка

```bash
openssl x509 -in ca.pem -text -noout | head -30
```

Ожидаемая строка: `Signature Algorithm: ecdsa-with-SHA256`.

### Verification (раздел CA)

```bash
openssl verify -CAfile ca.pem ca.pem
```

Ожидание: `ca.pem: OK`.

## Создание удостоверения ролевой учётной записи

Роль на логине — это имя учётной записи входа: инженер входит в
**ролевую учётную запись**, названную по роли (`ssh serv@device`), и
запрошенная роль равна имени этой УЗ. Отдельного запроса роли нет.

Дальше по сценарию используется роль `serv` («сервисный инженер») — для
неё в пакете есть готовый срез `dist/roles/serv.toml`, он понадобится в
[install.md](install.md) §8. Учётная запись входа тоже называется
`serv`; заводим её там же, вместе с ролевым хранилищем.

### 4. Ключ и CSR

```bash
openssl ecparam -name prime256v1 -genkey -noout -out serv.key
chmod 0600 serv.key
openssl req -new -key serv.key -out serv.csr \
    -subj "/CN=service-engineer/UID=serv"
```

Личность инженера живёт в удостоверении и в журнале выдачи, а не в
имени учётной записи входа. На допуск `CN` не влияет: решение
принимается по расширениям из следующего раздела.

### 5. Расширения и подпись CSR

Лист обязан нести **два** расширения:

| Расширение | OID | Отвечает на вопрос |
|------------|-----|--------------------|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | на каких устройствах предъявитель вправе входить |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | какие роли предъявитель вправе активировать |

Каждое — `SEQUENCE OF UTF8String`; `pam_cert_allowed_roles` выпускается
некритичным. OID и ASN.1-синтаксис — из [cert-issuance.md](cert-issuance.md).

Отдельного списка разрешённых учётных записей нет и не нужно. Имя
учётной записи входа и есть роль, поэтому `pam_cert_allowed_roles`
отвечает сразу на оба вопроса — «какие роли предъявитель вправе
активировать» и «в какие учётные записи он пущен»: это одна и та же
строка. Два списка над одной строкой описывали бы нереализуемое
состояние «пущен в `serv`, но не вправе быть `serv`».

Без любого из двух модуль отклоняет аутентификацию **fail-closed**:
отсутствие host-расширения даёт `HostExtensionMissing`, отсутствие
`pam_cert_allowed_roles` означает, что удостоверение не даёт ни одной
роли, — а роль требуется на каждом входе. В обоих случаях [install.md
§7](install.md#7-авторизация-расширения-удостоверения) не найдёт OID в
удостоверении, а `pamtester` в [install.md
§10](install.md#10-smoke-тест-через-pamtester) не пройдёт.

Сначала узнаём `host_id_hash` этой машины — тот источник, что демон
использует сейчас (строка с `active_under_current_config=yes`, столбец
`hash_hex`). Это снимается **с целевой Astra-машины** — tessera там
уже должна быть установлена (`install.md` §1–§2):

```bash
HOST_HASH=$(sudo tessera dump-host-id | awk -F'\t' '$7 == "yes" { print $3 }')
echo "host_id_hash = ${HOST_HASH}"   # 64 hex-символа
```

Собираем `extfile` с обоими расширениями (хост — только эта машина,
роль, она же учётная запись входа, — только `serv`):

```bash
cat > serv.ext <<EOF
extendedKeyUsage = clientAuth
keyUsage = critical,digitalSignature

# Хост: только эта машина (host_id_hash получен выше)
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb
# Роли, они же учётные записи входа: только serv
2.25.185305973969816596290730578528098241367 = ASN1:SEQUENCE:ar

[ hb ]
e0 = UTF8String:sha256:${HOST_HASH}

[ ar ]
e0 = UTF8String:serv
EOF
```

Подписываем CSR с этим `extfile`:

```bash
openssl x509 -req -in serv.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out serv.pem -days 365 \
    -extfile serv.ext
```

### Проверка OID

```bash
openssl x509 -in serv.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|185305973969816596290730578528098241367)'
```

Ожидание: обе строки с дотированными OID присутствуют в выводе.

### 6. Упаковка в P12

```bash
openssl pkcs12 -export -inkey serv.key -in serv.pem \
    -out serv.p12 -name serv -passout pass:test
chmod 0600 serv.p12
```

### Verification (раздел удостоверения)

```bash
openssl pkcs12 -in serv.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Ожидание: `subject=CN=service-engineer, UID=serv` (точный порядок RDN
зависит от версии OpenSSL).

Результат всего раздела — `ca.pem` и `serv.p12` в `/tmp/ca/`, готовые к
переносу на USB-носитель ([install.md §5](install.md#5-подготовка-usb-носителя-режим-pkcs12--mode-a)).
