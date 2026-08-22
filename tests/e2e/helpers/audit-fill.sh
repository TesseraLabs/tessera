#!/bin/sh
# Заполняет журнал аудита до потолка и возвращает то, чем это кончилось.
#
# Цикл в YAML-шаг не помещается (формат этого и не поддерживает), поэтому он
# здесь. Хелпер ничего не решает за кейс: он лишь пишет аннотации до первой
# остановки и отдаёт наружу код возврата и вывод последней команды — их и
# проверяет кейс.
#
#   audit-fill.sh <журнал> <потолок в байтах> [refuse|rotate]
#
# Коды возврата:
#   0  — запись прошла (режим rotate: журнал провернулся и пишет дальше)
#   3  — журнал заполнен и настроен на отказ (режим refuse)
#   2  — что-то другое остановило запись
#   64 — неверные аргументы
set -eu

if [ $# -lt 2 ]; then
    echo "usage: audit-fill.sh <journal> <ceiling-bytes> [refuse|rotate]" >&2
    exit 64
fi

journal=$1
ceiling=$2
when_full=${3:-refuse}

case "$when_full" in
    refuse|rotate) ;;
    *) echo "audit-fill.sh: unknown behaviour: $when_full" >&2; exit 64 ;;
esac

# Верхняя граница числа попыток, а не ожидаемое число записей: сколько именно
# записей поместится в потолок, решает длина строки, и кейс на неё не опирается.
attempts=64
index=0
status=0
output=""

while [ "$index" -lt "$attempts" ]; do
    index=$((index + 1))
    set +e
    output=$(tessera audit annotate \
        --file "$journal" \
        --kind e2e.audit \
        --data "{\"n\":$index}" \
        --ceiling-bytes "$ceiling" \
        --when-full "$when_full" 2>&1)
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        break
    fi
    # В режиме rotate останавливаемся на первом провороте: второй — отдельная
    # гарантия (отказ вместо затирания уже отставленной цепочки), и смешивать
    # их в одном кейсе значит проверять не то.
    if [ "$when_full" = rotate ] && [ -e "$journal.1" ]; then
        break
    fi
done

printf '%s\n' "$output"
exit "$status"
