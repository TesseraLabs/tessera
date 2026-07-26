/*
 * pam-drive — минимальный драйвер PAM-фаз для e2e-контура Tessera.
 *
 * Зачем свой драйвер вместо pamtester: в репозиториях Astra пакета pamtester нет,
 * а без него нельзя прогонять PAM-сценарии на целевом дистрибутиве. Плюс pamtester
 * возвращает один общий код, а кейсам нужно различать «auth прошла, account отказал»
 * от «auth отказала» — эти два исхода означают разные дефекты продукта.
 *
 * Использование:
 *     pam-drive <service> <user> <phase> [<phase> ...]
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
 * Код возврата: 0, если все запрошенные фазы вернули PAM_SUCCESS; иначе код первой
 * упавшей фазы (значения PAM укладываются в 1..~32, с диапазоном exit-кодов не спорят).
 * Ошибка аргументов или самого драйвера — 64 (EX_USAGE) и 70 (EX_SOFTWARE): их нельзя
 * спутать с вердиктом PAM, иначе сбой стенда прочитается как отказ продукта.
 */

#include <security/pam_appl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    fputs("usage: pam-drive <service> <user> <phase> [<phase> ...]\n"
          "  phase: authenticate | acct_mgmt | open_session | close_session\n"
          "  secret (password/PIN) is read as a single line from stdin\n"
          "  output: one line per phase, e.g. \"auth: PAM_SUCCESS (0)\"\n"
          "  exit: 0 if all phases succeeded, otherwise the code of the first failure\n",
          out);
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
    if (argc < 4) {
        usage(stderr);
        return EXIT_USAGE;
    }

    const char *service = argv[1];
    const char *user = argv[2];

    /* Неизвестную фазу ловим до pam_start: иначе часть сценария уже исполнится,
     * а кейс получит смесь настоящих вердиктов и ошибки драйвера. */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "authenticate") != 0 &&
            strcmp(argv[i], "acct_mgmt") != 0 &&
            strcmp(argv[i], "open_session") != 0 &&
            strcmp(argv[i], "close_session") != 0) {
            fprintf(stderr, "pam-drive: unknown phase: %s\n", argv[i]);
            usage(stderr);
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
        return EXIT_INTERNAL;
    }

    int first_failure = 0;
    for (int i = 3; i < argc; i++) {
        const char *tag = NULL;
        int prc = run_phase(pamh, argv[i], &tag);
        printf("%s: %s (%d)\n", tag != NULL ? tag : argv[i], pam_code_name(prc), prc);
        fflush(stdout);
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

    if (first_failure != 0) {
        return first_failure;
    }
    return end_rc == PAM_SUCCESS ? 0 : EXIT_INTERNAL;
}
