/*
 * pam-drive — минимальный драйвер PAM-фаз для e2e-контура Tessera.
 *
 * Зачем свой драйвер вместо pamtester: в репозиториях Astra пакета pamtester нет,
 * а без него нельзя прогонять PAM-сценарии на целевом дистрибутиве. Плюс pamtester
 * возвращает один общий код, а кейсам нужно различать «auth прошла, account отказал»
 * от «auth отказала» — эти два исхода означают разные дефекты продукта.
 *
 * Использование:
 *     pam-drive [--show-creds] [--answers-per-prompt] [--no-user]
 *               [--xdisplay <display>] [--xauthdata <name>:<hex>]
 *               <service> <user> <phase> [<phase> ...]
 *     phase ∈ { authenticate, acct_mgmt, open_session, close_session }
 *
 * `--no-user` ведёт разговор без имени учётной записи: pam_start получает NULL,
 * и добыть имя обязан стек. Так работает штатный греетер fly-dm с плагином
 * modern — он не задаёт PAM_USER и отвечает именем из формы на первый промпт с
 * эхом. Позиционный аргумент <user> всё равно обязателен (запись кейса остаётся
 * одинаковой), но в pam_start не уходит.
 *
 * `--xdisplay` и `--xauthdata` выставляют items PAM_XDISPLAY и PAM_XAUTHDATA —
 * тот единственный канал, которым дисплей-менеджер называет модулю свой дисплей
 * и права на него. У процесса самого fly-dm переменных DISPLAY и XAUTHORITY нет,
 * поэтому разговор, ведущийся через окружение, проверял бы не тот путь. Данные
 * куки задаются шестнадцатеричной строкой: в ней есть непечатаемые байты, и
 * аргументом командной строки они не проезжают.
 *
 * Пароль/PIN читается со stdin (одна строка). Терминала нет: conversation-функция
 * отвечает на PAM_PROMPT_ECHO_OFF/ON заранее прочитанным значением, а информационные
 * и сообщения об ошибке от модуля уходят в stderr — так вывод фаз в stdout остаётся
 * машиночитаемым и не смешивается с диагностикой модуля.
 *
 * Одна строка на все промпты — поведение по умолчанию, и оно проверяется кейсами:
 * разговор, спрашивающий PIN трижды, получает один и тот же неверный PIN и упирается
 * в бюджет попыток. Разговоры, где промпты означают разное (оператор, PIN, код),
 * так не проехать — для них есть `--answers-per-prompt`: stdin читается построчно,
 * i-й промпт получает i-ю строку. Строка читается В МОМЕНТ промпта, а не заранее:
 * ответ на последний промпт разговора кодов вычисляется по challenge, который до
 * первых двух ответов ещё не напечатан, и вызывающий подаёт его в тот же stdin позже.
 * Кончившийся stdin — ошибка разговора, а не пустой ответ: сценарий, где промптов
 * больше, чем ответов, обязан падать явно, иначе модуль получит пустую строку и кейс
 * прочитает отказ продукта вместо ошибки стенда.
 *
 * Вывод: ровно одна строка на фазу в stdout, формат `<тег>: <PAM_КОНСТАНТА> (<код>)`,
 * например `auth: PAM_SUCCESS (0)`. Каждая строка — один смысл, чтобы ожидания кейса
 * писались регекспом по конкретной фазе.
 *
 * С `--show-creds` после успешной фазы open_session печатается фактическое состояние
 * процесса — то, что роль обязана была принести в сессию (группы, лимиты, окружение).
 * Без снимка состояния кейсу нечего проверять: вердикт PAM_SUCCESS сам по себе не
 * говорит, применилось ли хоть что-то. Снимок снимается только при успехе фазы:
 * после отказа состояние процесса — это состояние до сессии, и сравнивать его с
 * ожиданиями роли бессмысленно.
 *
 * Код возврата: 0, если все запрошенные фазы вернули PAM_SUCCESS; иначе код первой
 * упавшей фазы (значения PAM укладываются в 1..~32, с диапазоном exit-кодов не спорят).
 * Ошибка аргументов или самого драйвера — 64 (EX_USAGE) и 70 (EX_SOFTWARE): их нельзя
 * спутать с вердиктом PAM, иначе сбой стенда прочитается как отказ продукта.
 */

#include <security/pam_appl.h>

#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#define EXIT_USAGE 64
#define EXIT_INTERNAL 70

/* Ответ conversation-функции. Живёт до конца процесса: PAM освобождает выданные
 * ему буферы сам, поэтому копия отдаётся каждый раз заново, а оригинал остаётся
 * в этой переменной. */
static char *g_secret = NULL;

/* Режим `--answers-per-prompt`: строка со stdin читается на КАЖДЫЙ промпт, и
 * читается в момент промпта, а не заранее. Разговор кодов иначе не проехать:
 * код вычисляется по напечатанному challenge, то есть последний ответ ещё не
 * существует, когда даются первые два. Вычитывание stdin до старта PAM встало
 * бы в тупик — драйвер ждал бы EOF от того, кто ждёт challenge от драйвера.
 * Отданные ответы остаются здесь, чтобы затереть их перед выходом. */
static char **g_answers = NULL;
static size_t g_answer_count = 0;
static int g_per_prompt = 0;

static const char *pam_code_name(int code)
{
    switch (code) {
    case PAM_SUCCESS:              return "PAM_SUCCESS";
    case PAM_OPEN_ERR:             return "PAM_OPEN_ERR";
    case PAM_SYMBOL_ERR:           return "PAM_SYMBOL_ERR";
    case PAM_SERVICE_ERR:          return "PAM_SERVICE_ERR";
    case PAM_SYSTEM_ERR:           return "PAM_SYSTEM_ERR";
    case PAM_BUF_ERR:              return "PAM_BUF_ERR";
    case PAM_PERM_DENIED:          return "PAM_PERM_DENIED";
    case PAM_AUTH_ERR:             return "PAM_AUTH_ERR";
    case PAM_CRED_INSUFFICIENT:    return "PAM_CRED_INSUFFICIENT";
    case PAM_AUTHINFO_UNAVAIL:     return "PAM_AUTHINFO_UNAVAIL";
    case PAM_USER_UNKNOWN:         return "PAM_USER_UNKNOWN";
    case PAM_MAXTRIES:             return "PAM_MAXTRIES";
    case PAM_NEW_AUTHTOK_REQD:     return "PAM_NEW_AUTHTOK_REQD";
    case PAM_ACCT_EXPIRED:         return "PAM_ACCT_EXPIRED";
    case PAM_SESSION_ERR:          return "PAM_SESSION_ERR";
    case PAM_CRED_UNAVAIL:         return "PAM_CRED_UNAVAIL";
    case PAM_CRED_EXPIRED:         return "PAM_CRED_EXPIRED";
    case PAM_CRED_ERR:             return "PAM_CRED_ERR";
    case PAM_NO_MODULE_DATA:       return "PAM_NO_MODULE_DATA";
    case PAM_CONV_ERR:             return "PAM_CONV_ERR";
    case PAM_AUTHTOK_ERR:          return "PAM_AUTHTOK_ERR";
    case PAM_AUTHTOK_RECOVERY_ERR: return "PAM_AUTHTOK_RECOVERY_ERR";
    case PAM_AUTHTOK_LOCK_BUSY:    return "PAM_AUTHTOK_LOCK_BUSY";
    case PAM_AUTHTOK_DISABLE_AGING:return "PAM_AUTHTOK_DISABLE_AGING";
    case PAM_TRY_AGAIN:            return "PAM_TRY_AGAIN";
    case PAM_IGNORE:               return "PAM_IGNORE";
    case PAM_ABORT:                return "PAM_ABORT";
    case PAM_AUTHTOK_EXPIRED:      return "PAM_AUTHTOK_EXPIRED";
    case PAM_MODULE_UNKNOWN:       return "PAM_MODULE_UNKNOWN";
    case PAM_BAD_ITEM:             return "PAM_BAD_ITEM";
    default:                       return "PAM_UNKNOWN";
    }
}

/* Читает одну строку со stdin без ограничения длины. Возвращает NULL,
 * если stdin пуст, — это не ошибка: фазе может не понадобиться секрет. */
static char *read_secret_line(void)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t len = getline(&line, &cap, stdin);
    if (len < 0) {
        free(line);
        return NULL;
    }
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    return line;
}

/* Берёт очередной ответ построчного режима. Строка читается прямо сейчас —
 * тот, кто ведёт разговор, мог ещё не знать её, когда давал предыдущую.
 * Возвращает NULL на конце stdin и на нехватке памяти: и то, и другое означает,
 * что отвечать нечем. Отданная строка остаётся во владении драйвера и живёт до
 * `wipe_answers`, поэтому вызывающий её не освобождает. */
static char *take_answer_line(void)
{
    char *line = read_secret_line();
    if (line == NULL) {
        return NULL;
    }
    char **grown = realloc(g_answers, (g_answer_count + 1) * sizeof(*g_answers));
    if (grown == NULL) {
        memset(line, 0, strlen(line));
        free(line);
        return NULL;
    }
    g_answers = grown;
    g_answers[g_answer_count++] = line;
    return line;
}

static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata)
{
    (void)appdata;

    if (num_msg <= 0 || resp == NULL) {
        return PAM_CONV_ERR;
    }

    struct pam_response *replies = calloc((size_t)num_msg, sizeof(*replies));
    if (replies == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON: {
            /* Промпт печатаем в stderr, а не в stdout: его текст не является
             * результатом фазы и не должен попадать под регекспы кейса. */
            fprintf(stderr, "prompt: %s\n", msg[i]->msg ? msg[i]->msg : "");
            const char *answer = g_secret != NULL ? g_secret : "";
            if (g_per_prompt) {
                char *line = take_answer_line();
                if (line == NULL) {
                    /* stdin кончился раньше промптов. Отдать пустую строку
                     * значило бы подсунуть модулю неверный ввод и выдать сбой
                     * стенда за отказ продукта, поэтому разговор обрывается
                     * ошибкой. */
                    fprintf(stderr,
                            "pam-drive: stdin кончился на промпте %zu — ответов меньше, чем промптов\n",
                            g_answer_count + 1);
                    for (int j = 0; j < i; j++) {
                        free(replies[j].resp);
                    }
                    free(replies);
                    return PAM_CONV_ERR;
                }
                answer = line;
            }
            replies[i].resp = strdup(answer);
            if (replies[i].resp == NULL) {
                for (int j = 0; j < i; j++) {
                    free(replies[j].resp);
                }
                free(replies);
                return PAM_BUF_ERR;
            }
            break;
        }
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            fprintf(stderr, "module: %s\n", msg[i]->msg ? msg[i]->msg : "");
            replies[i].resp = NULL;
            break;
        default:
            for (int j = 0; j < i; j++) {
                free(replies[j].resp);
            }
            free(replies);
            return PAM_CONV_ERR;
        }
        replies[i].resp_retcode = 0;
    }

    *resp = replies;
    return PAM_SUCCESS;
}

/* Затирание ответов до free: процесс короткоживущий, но его память может попасть
 * в core dump артефактов провалившегося кейса, а среди ответов есть PIN. */
static void wipe_answers(void)
{
    if (g_secret != NULL) {
        memset(g_secret, 0, strlen(g_secret));
        free(g_secret);
        g_secret = NULL;
    }
    for (size_t i = 0; i < g_answer_count; i++) {
        if (g_answers[i] != NULL) {
            memset(g_answers[i], 0, strlen(g_answers[i]));
            free(g_answers[i]);
        }
    }
    free(g_answers);
    g_answers = NULL;
    g_answer_count = 0;
}

/* Значение одной шестнадцатеричной цифры либо -1. Регистр любой; больше
 * ничего не принимается. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Разбирает шестнадцатеричную строку в байты. Возвращает NULL на нечётной длине
 * и на любом не-hex символе: молча принятая половина куки дала бы «оверлей не
 * поднялся» вместо ошибки стенда. Длина результата — в *out_len. */
static unsigned char *parse_hex(const char *hex, size_t *out_len)
{
    size_t len = strlen(hex);
    if (len == 0 || len % 2 != 0) {
        return NULL;
    }
    unsigned char *bytes = calloc(len / 2, 1);
    if (bytes == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len / 2; i++) {
        /* Посимвольно, а не strtoul: тот принимает ведущие пробелы и знак, то
         * есть " f" и "+f" прошли бы как байты, и куки молча поехала бы другая.
         * Стенд обязан спотыкаться на своём аргументе, а не подменять его. */
        int high = hex_digit(hex[2 * i]);
        int low = hex_digit(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (unsigned char)((high << 4) | low);
    }
    *out_len = len / 2;
    return bytes;
}

static void usage(FILE *out)
{
    fputs("usage: pam-drive [--show-creds] [--answers-per-prompt] [--no-user]\n"
          "                 [--xdisplay <display>] [--xauthdata <name>:<hex>]\n"
          "                 <service> <user> <phase> [<phase> ...]\n"
          "  phase: authenticate | acct_mgmt | open_session | close_session\n"
          "  secret (password/PIN) is read as a single line from stdin\n"
          "  output: one line per phase, e.g. \"auth: PAM_SUCCESS (0)\"\n"
          "  --show-creds: after a successful open_session, dump the resulting process\n"
          "                state (uid, gid, groups, groupnames, limit_nofile, pamenv),\n"
          "                one fact per line\n"
          "  --answers-per-prompt: read one stdin line per prompt, as the prompt arrives,\n"
          "                answering the i-th prompt with the i-th line; a prompt met with\n"
          "                end of input ends the conversation with an error rather than an\n"
          "                empty answer\n"
          "  --no-user: start the transaction with no user name at all (NULL), the way a\n"
          "                display manager greeter does; the positional <user> is then only\n"
          "                the name the case is written about\n"
          "  --xdisplay <display>: set PAM_XDISPLAY, as a display manager does\n"
          "  --xauthdata <name>:<hex>: set PAM_XAUTHDATA, e.g. MIT-MAGIC-COOKIE-1:0a1b...\n"
          "  exit: 0 if all phases succeeded, otherwise the code of the first failure\n",
          out);
}

/* Ключи окружения, значения которых не печатаются. pam_getenvlist отдаёт всё,
 * что выставили модули стека, включая чужие: в стенде рядом с pam_tessera могут
 * стоять модули, кладущие в окружение ключ/пароль/тикет. Лог кейса переживает
 * прогон и уезжает в артефакты, поэтому значение таких переменных заменяется на
 * <redacted> — имя переменной остаётся, чтобы кейс всё же мог проверить сам факт
 * её появления. Сравнение подстрокой, а не по полному имени: модули дают своим
 * переменным разные префиксы, и полный перечень имён не составить. Пути к файлам
 * с секретами (KRB5CCNAME и подобные) под фильтр намеренно не попадают: сам путь
 * секретом не является, а кейсу он нужен целиком. */
static const char *const SENSITIVE_ENV_MARKERS[] = {
    "PASS", "SECRET", "TOKEN", "AUTHTOK", "PIN", "KEY", "CRED", "COOKIE",
};

static int env_is_sensitive(const char *entry, size_t name_len)
{
    for (size_t m = 0; m < sizeof(SENSITIVE_ENV_MARKERS) / sizeof(*SENSITIVE_ENV_MARKERS); m++) {
        const char *marker = SENSITIVE_ENV_MARKERS[m];
        size_t marker_len = strlen(marker);
        if (marker_len > name_len) {
            continue;
        }
        for (size_t i = 0; i + marker_len <= name_len; i++) {
            if (strncmp(entry + i, marker, marker_len) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* Управляющие символы в значении экранируются: перевод строки внутри переменной
 * разорвал бы факт на две строки и сдвинул разбор вывода у кейса. */
static void print_escaped(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            printf("\\x%02X", *p);
        } else {
            fputc((int)*p, stdout);
        }
    }
}

/* Лимит печатается как два числа, «мягкий жёсткий». RLIM_INFINITY выводится
 * словом: числовое представление бесконечности разное на разных ABI, и кейс,
 * написанный по одному значению, соврал бы на другой архитектуре. */
static void print_limit(const char *tag, int resource)
{
    struct rlimit rl;
    if (getrlimit(resource, &rl) != 0) {
        return;
    }
    char soft[32];
    char hard[32];
    if (rl.rlim_cur == RLIM_INFINITY) {
        snprintf(soft, sizeof(soft), "unlimited");
    } else {
        snprintf(soft, sizeof(soft), "%llu", (unsigned long long)rl.rlim_cur);
    }
    if (rl.rlim_max == RLIM_INFINITY) {
        snprintf(hard, sizeof(hard), "unlimited");
    } else {
        snprintf(hard, sizeof(hard), "%llu", (unsigned long long)rl.rlim_max);
    }
    printf("%s: %s %s\n", tag, soft, hard);
}

/* Снимок состояния процесса после открытия сессии. Печатается в stdout рядом с
 * вердиктами фаз, по одному факту на строку и без переносов внутри значения —
 * ожидания кейса пишутся регекспом на отдельную строку. */
static void print_creds(pam_handle_t *pamh)
{
    /* uid/gid эффективные, а не реальные: enforcement роли (если он есть) меняет
     * именно рабочие идентификаторы процесса, под которыми пойдёт сессия. */
    printf("uid: %u\n", (unsigned)geteuid());
    printf("gid: %u\n", (unsigned)getegid());

    /* Размер списка спрашивается отдельным вызовом: между вызовами он в принципе
     * может измениться, поэтому короткий буфер не подойдёт, а NGROUPS_MAX на
     * некоторых системах великоват для стека. */
    int ngroups = getgroups(0, NULL);
    if (ngroups < 0) {
        fprintf(stderr, "pam-drive: getgroups failed\n");
    } else {
        gid_t *groups = NULL;
        if (ngroups > 0) {
            groups = calloc((size_t)ngroups, sizeof(*groups));
            if (groups == NULL) {
                fprintf(stderr, "pam-drive: out of memory reading groups\n");
                ngroups = -1;
            } else {
                ngroups = getgroups(ngroups, groups);
            }
        }
        if (ngroups >= 0) {
            fputs("groups:", stdout);
            for (int i = 0; i < ngroups; i++) {
                printf(" %u", (unsigned)groups[i]);
            }
            fputc('\n', stdout);

            /* Имена печатаются отдельной строкой: gid зависят от порядка создания
             * учётных записей в стенде, а имена групп задаются ролью и стабильны —
             * по ним и пишутся ожидания. Неразрешимый gid остаётся в строке как
             * `#<gid>`, чтобы позиции в двух строках совпадали. */
            fputs("groupnames:", stdout);
            for (int i = 0; i < ngroups; i++) {
                struct group *gr = getgrgid(groups[i]);
                if (gr != NULL && gr->gr_name != NULL) {
                    printf(" %s", gr->gr_name);
                } else {
                    printf(" #%u", (unsigned)groups[i]);
                }
            }
            fputc('\n', stdout);
        }
        free(groups);
    }

    print_limit("limit_nofile", RLIMIT_NOFILE);

    /* pam_getenvlist отдаёт вызывающему владение и массивом, и строками —
     * освобождаем и то, и другое. */
    char **env = pam_getenvlist(pamh);
    if (env != NULL) {
        for (size_t i = 0; env[i] != NULL; i++) {
            const char *eq = strchr(env[i], '=');
            if (eq != NULL && env_is_sensitive(env[i], (size_t)(eq - env[i]))) {
                printf("pamenv: %.*s=<redacted>\n", (int)(eq - env[i]), env[i]);
            } else {
                /* Запись без '=' форматно не переменная, но печатается как есть:
                 * кейс должен увидеть странное содержимое стека, а не тишину. */
                fputs("pamenv: ", stdout);
                print_escaped(env[i]);
                fputc('\n', stdout);
            }
            free(env[i]);
        }
        free(env);
    }

    fflush(stdout);
}

/* Тег фазы в выводе намеренно короткий и стабильный: по нему пишутся ожидания
 * кейсов, переименование тега сломает весь реестр. */
static int run_phase(pam_handle_t *pamh, const char *phase, const char **tag_out)
{
    if (strcmp(phase, "authenticate") == 0) {
        *tag_out = "auth";
        return pam_authenticate(pamh, 0);
    }
    if (strcmp(phase, "acct_mgmt") == 0) {
        *tag_out = "acct";
        return pam_acct_mgmt(pamh, 0);
    }
    if (strcmp(phase, "open_session") == 0) {
        *tag_out = "open_session";
        return pam_open_session(pamh, 0);
    }
    if (strcmp(phase, "close_session") == 0) {
        *tag_out = "close_session";
        return pam_close_session(pamh, 0);
    }
    *tag_out = NULL;
    return PAM_ABORT;
}

int main(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(stdout);
        return 0;
    }

    /* Флаги вычёсываются из argv отдельным проходом, а позиционные аргументы
     * собираются в свой список. Так `--show-creds` можно поставить где угодно,
     * и уже написанные вызовы без флага разбираются ровно как раньше. */
    int show_creds = 0;
    int no_user = 0;
    const char *xdisplay = NULL;
    const char *xauthdata = NULL;
    const char **args = calloc((size_t)argc, sizeof(*args));
    if (args == NULL) {
        fprintf(stderr, "pam-drive: out of memory\n");
        return EXIT_INTERNAL;
    }
    int nargs = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--show-creds") == 0) {
            show_creds = 1;
        } else if (strcmp(argv[i], "--answers-per-prompt") == 0) {
            g_per_prompt = 1;
        } else if (strcmp(argv[i], "--no-user") == 0) {
            no_user = 1;
        } else if (strcmp(argv[i], "--xdisplay") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "pam-drive: --xdisplay без значения\n");
                free(args);
                return EXIT_USAGE;
            }
            xdisplay = argv[++i];
        } else if (strcmp(argv[i], "--xauthdata") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "pam-drive: --xauthdata без значения\n");
                free(args);
                return EXIT_USAGE;
            }
            xauthdata = argv[++i];
        } else {
            args[nargs++] = argv[i];
        }
    }

    if (nargs < 3) {
        usage(stderr);
        free(args);
        return EXIT_USAGE;
    }

    const char *service = args[0];
    const char *user = args[1];

    /* Неизвестную фазу ловим до pam_start: иначе часть сценария уже исполнится,
     * а кейс получит смесь настоящих вердиктов и ошибки драйвера. */
    for (int i = 2; i < nargs; i++) {
        if (strcmp(args[i], "authenticate") != 0 &&
            strcmp(args[i], "acct_mgmt") != 0 &&
            strcmp(args[i], "open_session") != 0 &&
            strcmp(args[i], "close_session") != 0) {
            fprintf(stderr, "pam-drive: unknown phase: %s\n", args[i]);
            usage(stderr);
            free(args);
            return EXIT_USAGE;
        }
    }

    /* В построчном режиме stdin читается по ходу разговора, поэтому здесь
     * не читается ничего: строка берётся в момент промпта. */
    if (!g_per_prompt) {
        g_secret = read_secret_line();
    }

    struct pam_conv conv = { conv_fn, NULL };
    pam_handle_t *pamh = NULL;

    /* NULL, а не пустая строка: это два разных состояния транзакции, и греетер
     * modern оставляет именно первое — имени нет вовсе, добыть его обязан стек. */
    int rc = pam_start(service, no_user ? NULL : user, &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        /* Сообщение об ошибке берём у PAM, но handle ещё нет — pam_strerror
         * с NULL допустим и даёт общий текст. */
        fprintf(stderr, "pam-drive: pam_start failed: %s (%d)\n",
                pam_code_name(rc), rc);
        wipe_answers();
        free(args);
        return EXIT_INTERNAL;
    }

    /* Items выставляются до первой фазы: модуль читает их в начале разговора,
     * а выставленные позже они описывали бы уже не тот разговор. Сбой установки
     * — ошибка стенда (кейс просил именно этот канал), а не вердикт продукта. */
    if (xdisplay != NULL) {
        rc = pam_set_item(pamh, PAM_XDISPLAY, xdisplay);
        if (rc != PAM_SUCCESS) {
            fprintf(stderr, "pam-drive: pam_set_item(PAM_XDISPLAY) failed: %s (%d)\n",
                    pam_code_name(rc), rc);
            pam_end(pamh, rc);
            wipe_answers();
            free(args);
            return EXIT_INTERNAL;
        }
    }
    if (xauthdata != NULL) {
        const char *colon = strchr(xauthdata, ':');
        if (colon == NULL) {
            fprintf(stderr, "pam-drive: --xauthdata ожидает <name>:<hex>\n");
            pam_end(pamh, PAM_ABORT);
            wipe_answers();
            free(args);
            return EXIT_USAGE;
        }
        size_t name_len = (size_t)(colon - xauthdata);
        char *name = strndup(xauthdata, name_len);
        size_t data_len = 0;
        unsigned char *data = parse_hex(colon + 1, &data_len);
        if (name == NULL || data == NULL) {
            fprintf(stderr, "pam-drive: --xauthdata: имя или шестнадцатеричные данные негодны\n");
            free(name);
            free(data);
            pam_end(pamh, PAM_ABORT);
            wipe_answers();
            free(args);
            return EXIT_USAGE;
        }
        struct pam_xauth_data xauth = {
            .namelen = (int)name_len,
            .name = name,
            .datalen = (int)data_len,
            .data = (char *)data,
        };
        /* PAM копирует структуру себе, поэтому буферы освобождаются сразу. */
        rc = pam_set_item(pamh, PAM_XAUTHDATA, &xauth);
        free(name);
        free(data);
        if (rc != PAM_SUCCESS) {
            fprintf(stderr, "pam-drive: pam_set_item(PAM_XAUTHDATA) failed: %s (%d)\n",
                    pam_code_name(rc), rc);
            pam_end(pamh, rc);
            wipe_answers();
            free(args);
            return EXIT_INTERNAL;
        }
    }

    int first_failure = 0;
    for (int i = 2; i < nargs; i++) {
        const char *tag = NULL;
        int prc = run_phase(pamh, args[i], &tag);
        printf("%s: %s (%d)\n", tag != NULL ? tag : args[i], pam_code_name(prc), prc);
        fflush(stdout);
        /* Снимок печатается сразу после строки вердикта той фазы, которая его
         * породила: в сценарии с несколькими сессиями иначе не понять, к какой
         * из них относится состояние. */
        if (show_creds && prc == PAM_SUCCESS && strcmp(args[i], "open_session") == 0) {
            print_creds(pamh);
        }
        if (prc != PAM_SUCCESS && first_failure == 0) {
            first_failure = prc;
            /* Остальные фазы всё равно исполняем: кейсу бывает нужно увидеть,
             * что открытие сессии не произошло после отказавшей auth-фазы. */
        }
    }

    /* pam_end вызывается в любом случае — включая путь ранней ошибки выше. */
    int end_rc = pam_end(pamh, first_failure);
    pamh = NULL;
    if (end_rc != PAM_SUCCESS) {
        fprintf(stderr, "pam-drive: pam_end failed: %s (%d)\n",
                pam_code_name(end_rc), end_rc);
    }

    wipe_answers();

    free(args);

    if (first_failure != 0) {
        return first_failure;
    }
    return end_rc == PAM_SUCCESS ? 0 : EXIT_INTERNAL;
}
