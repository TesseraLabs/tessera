#!/usr/bin/env python3
"""Считает код входа по контракту Tessera Codes, не пользуясь крейтами Tessera.

Зачем это существует. Сквозной тест сравнивает код, посчитанный устройством, с
кодом, посчитанным выдающей стороной, — но обе стороны зовут одни и те же
примитивы одного открытого ядра. Общая ошибка в них согласованно не заметится:
две реализации, выведенные из одного кода, ошибаются одинаково. Поэтому
ожидаемый код для фикстурной попытки считается ЗДЕСЬ, по описанию формата, и
замораживается в файле, который крейт не пишет.

Что здесь чужое, а что своё. ECDH выполняет `openssl pkeyutl -derive` — внешний
инструмент, не наш код. HKDF-SHA256 написан прямо по RFC 5869, HMAC и SHA-256
взяты из стандартной библиотеки Python. Каноническая упаковка полей, несмещённое
усечение и алфавит написаны по описанию формата, а не переведены из Rust: если
бы они были переводом, они повторили бы ту самую ошибку, которую вектор должен
ловить.

Запуск:

    python3 tools/codes-golden-code.py \\
        crates/tessera_core/tests/fixtures/codes/stand

Печатает код одной строкой. Он же лежит в `code-vector-expected.txt` того же
каталога; расхождение означает, что кто-то поменял формат.
"""

import hashlib
import hmac
import subprocess
import sys
from pathlib import Path

# Алфавит Crockford base32 в порядке значений: цифры и буквы без I, L, O и U.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
DECIMAL = "0123456789"

# Разделитель раундов усечения, вне пространства канонических входов.
RETRY_LABEL = b"/tessera-codes-contract/v1/truncate-retry/"

# Столько дополнительных раундов допускает контракт.
MAX_ROUNDS = 64


def field(value: bytes) -> bytes:
    """Одно поле канонической упаковки: длина четырьмя байтами и значение."""
    return len(value).to_bytes(4, "big") + value


def text_field(value: str) -> bytes:
    return field(value.encode("utf-8"))


def u32_field(value: int) -> bytes:
    """Целое поле: четыре байта значения, обёрнутые в ту же рамку длины."""
    return field(value.to_bytes(4, "big"))


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 по RFC 5869: extract и expand, написанные по тексту RFC."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def ecdh(private_pem: Path, peer_pem: Path) -> bytes:
    """Общий секрет Z. Считает openssl, а не этот скрипт и не крейты Tessera."""
    result = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-derive",
            "-inkey",
            str(private_pem),
            "-peerkey",
            str(peer_pem),
        ],
        capture_output=True,
        check=True,
    )
    return result.stdout


def render(value: int, alphabet: str, width: int) -> str:
    """Значение в алфавите, старший символ первым, фиксированной ширины."""
    radix = len(alphabet)
    symbols = []
    rest = value
    for _ in range(width):
        symbols.append(alphabet[rest % radix])
        rest //= radix
    return "".join(reversed(symbols))


def truncate(key: bytes, message: bytes, alphabet: str, width: int) -> str:
    """Несмещённое усечение MAC до кода.

    Выборка из 64 бит принимается только из наибольшего кратного диапазону
    отрезка пространства выборки. Сведение по модулю без этого перекосило бы
    низкие коды вверх, а перекос — ровно то, что ищет подбирающий код на
    клавиатуре.
    """
    radix = len(alphabet)
    code_range = radix**width
    space = 1 << 64
    limit = space - (space % code_range)

    for round_index in range(MAX_ROUNDS + 1):
        if round_index == 0:
            payload = message
        else:
            payload = message + RETRY_LABEL + round_index.to_bytes(4, "big")
        mac = hmac.new(key, payload, hashlib.sha256).digest()
        for offset in range(0, len(mac) - len(mac) % 8, 8):
            sample = int.from_bytes(mac[offset : offset + 8], "big")
            if sample < limit:
                return render(sample % code_range, alphabet, width)
    raise SystemExit("несмещённое усечение исчерпало раунды")


def read_inputs(path: Path) -> dict:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    bundle = Path(argv[1])
    inputs = read_inputs(bundle / "code-vector-inputs.txt")

    alphabet = {
        "crockford-base32": CROCKFORD,
        "decimal": DECIMAL,
    }[inputs["alphabet"]]
    width = int(inputs["code_len"])

    shared = ecdh(bundle / "agreement-key.pem", bundle / "attempt-ephemeral.pub.pem")

    # Контекст вывода ключа: значащая форма номера устройства и хеш билета.
    # Имена полей в байты не попадают — они существуют для диагностики, а рамка
    # у каждого поля своя, поэтому переставить или склеить их нельзя.
    context = text_field(inputs["device_number_significant"]) + field(
        bytes.fromhex(inputs["ticket_hash_sha256"])
    )
    key = hkdf_sha256(inputs["kdf_salt"].encode("utf-8"), shared, context)

    # Вход MAC: шесть полей в порядке контракта.
    canonical = (
        text_field(inputs["device_number_significant"])
        + u32_field(int(inputs["epoch"]))
        + text_field(inputs["nonce"])
        + text_field(inputs["role_id"])
        + u32_field(int(inputs["level"]))
        + text_field(inputs["engineer_id"])
    )

    print(truncate(key, canonical, alphabet, width))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
