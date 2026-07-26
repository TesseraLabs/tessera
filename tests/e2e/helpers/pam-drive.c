/*
 * pam-drive — минимальный драйвер PAM-фаз для e2e-контура Tessera.
 *
 * Зачем свой драйвер вместо pamtester: в репозиториях Astra пакета pamtester нет,
 * а без него нельзя прогонять PAM-сценарии на целевом дистрибутиве. Плюс pamtester
 * возвращает один общий код, а кейсам нужно различать «auth прошла, account отказал»
 * от «auth отказала» — эти два исхода означают разные дефекты продукта.
 *
 * Использование:
 *     pam-drive [--show-creds] <service> <user> <phase> [<phase> ...]
 *     phase ∈ { authenticate, acct_mgmt, open_session, close_session }
 *
 * Пароль/PIN читается со stdin (одна строка). Терминала нет: conversation-функция
 * отвечает на PAM_PROMPT_ECHO_OFF/ON заранее прочитанным значением, а информационные
 * и сообщения об ошибке от модуля уходят в stderr — так вывод фаз в stdout остаётся
 * машиночитаемым и не смешивается с диагностикой модуля.
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
        case PAM_PROMPT_ECHO_ON:
            /* Промпт печатаем в stderr, а не в stdout: его текст не является
             * результатом фазы и не должен попадать под регекспы кейса. */
            fprintf(stderr, "prompt: %s\n", msg[i]->msg ? msg[i]->msg : "");
            replies[i].resp = strdup(g_secret != NULL ? g_secret : "");
            if (replies[i].resp == NULL) {
                for (int j = 0; j < i; j++) {
                    free(replies[j].resp);
                }
                free(replies);
                return PAM_BUF_ERR;
            }
            break;
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

static void usage(FILE *out)
{
    fputs("usage: pam-drive [--show-creds] <service> <user> <phase> [<phase> ...]\n"
          "  phase: authenticate | acct_mgmt | open_session | close_session\n"
          "  secret (password/PIN) is read as a single line from stdin\n"
          "  output: one line per phase, e.g. \"auth: PAM_SUCCESS (0)\"\n"
          "  --show-creds: after a successful open_session, dump the resulting process\n"
          "                state (uid, gid, groups, groupnames, limit_nofile, pamenv),\n"
          "                one fact per line\n"
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
    const char **args = calloc((size_t)argc, sizeof(*args));
    if (args == NULL) {
        fprintf(stderr, "pam-drive: out of memory\n");
        return EXIT_INTERNAL;
    }
    int nargs = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--show-creds") == 0) {
            show_creds = 1;
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

    g_secret = read_secret_line();

    struct pam_conv conv = { conv_fn, NULL };
    pam_handle_t *pamh = NULL;

    int rc = pam_start(service, user, &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        /* Сообщение об ошибке берём у PAM, но handle ещё нет — pam_strerror
         * с NULL допустим и даёт общий текст. */
        fprintf(stderr, "pam-drive: pam_start failed: %s (%d)\n",
                pam_code_name(rc), rc);
        if (g_secret != NULL) {
            memset(g_secret, 0, strlen(g_secret));
            free(g_secret);
        }
        free(args);
        return EXIT_INTERNAL;
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

    if (g_secret != NULL) {
        /* Секрет затирается до free: процесс короткоживущий, но его память
         * может попасть в core dump артефактов провалившегося кейса. */
        memset(g_secret, 0, strlen(g_secret));
        free(g_secret);
        g_secret = NULL;
    }

    free(args);

    if (first_failure != 0) {
        return first_failure;
    }
    return end_rc == PAM_SUCCESS ? 0 : EXIT_INTERNAL;
}
