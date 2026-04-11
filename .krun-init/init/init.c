#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#if __FreeBSD__
#include <kenv.h>
#include <libutil.h>
#include <sys/param.h>
#else
#include <sys/statfs.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#if __linux__
#include <linux/reboot.h>
#include <linux/vm_sockets.h>
#include <sys/reboot.h>
#endif

#include "dhcp.h"
#include "jsmn.h"

#ifdef SEV
#include "tee/snp_attest.h"
#endif

#define KRUN_EXIT_CODE_IOCTL 0x7602

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12
#define CMDLINE_SECRET_PATH "/sfs/secrets/coco/cmdline"
#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_PASS_SIZE 512
#define MAX_TOKENS 16384

static int jsoneq(const char *, jsmntok_t *, const char *);

#ifdef SEV
static char *sev_get_luks_passphrase(int *);
static char *snp_get_luks_passphrase(char *, char *, char *, int *);
#endif

char DEFAULT_KRUN_INIT[] = "/bin/sh";

#if __FreeBSD__
static char *get_kenv(const char *name)
{
    static char kenv_value[KENV_MVALLEN + 1];
    if (kenv(KENV_GET, name, kenv_value, KENV_MVALLEN + 1) < 0) {
        return NULL;
    }
    return kenv_value;
}

#define getenv get_kenv

#define _PATH_CONSOLE "/dev/console"
#define _PATH_DEVNULL "/dev/null"
#define _PATH_INITLOG "/init.log"
/*
 * Start a session and allocate a controlling terminal.
 * Only called by children of init after forking.
 */
static void open_console(void)
{
    int fd;

    /*
     * Try to open /dev/console.  Open the device with O_NONBLOCK to
     * prevent potential blocking on a carrier.
     */
    revoke(_PATH_CONSOLE);
    if ((fd = open(_PATH_CONSOLE, O_RDWR | O_NONBLOCK)) != -1) {
        (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        if (login_tty(fd) == 0)
            return;
        close(fd);
    }

    /* No luck.  Log output to file if possible. */
    if ((fd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
        _exit(1);
    }
    if (fd != STDIN_FILENO) {
        dup2(fd, STDIN_FILENO);
        close(fd);
    }
    fd = open(_PATH_INITLOG, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1)
        dup2(STDIN_FILENO, STDOUT_FILENO);
    else if (fd != STDOUT_FILENO) {
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }
    dup2(STDOUT_FILENO, STDERR_FILENO);
}

#define KRUN_CONFIG_ISO_DEV "/dev/iso9660/KRUN_CONFIG"
#define ISO_CONFIG_FILE_PATH "/mnt/krun_config.json"

bool config_file_from_iso(const char **path)
{
    const char *iov_args[] = {"fstype", "cd9660", "fspath",
                              "/mnt",   "from",   KRUN_CONFIG_ISO_DEV};

    const int iovlen = sizeof(iov_args) / sizeof(iov_args[0]);
    struct iovec iov[iovlen];
    int i;

    struct stat st;
    // mkdir can fail with read-only fs error,
    // so we rather check if /mnt exists first
    if (stat("/mnt", &st) != 0) {
        if (errno != ENOENT) {
            perror("stat(/mnt)");
            exit(-1);
        }
        if (mkdir("/mnt", 0755) < 0) {
            perror("mkdir(/mnt)");
            exit(-1);
        }
    }

    for (i = 0; i < iovlen; i++) {
        iov[i].iov_base = (void *)iov_args[i];
        iov[i].iov_len = strlen(iov_args[i]) + 1;
    }

    if (nmount(iov, iovlen, MNT_RDONLY) < 0) {
        *path = NULL;
        return false;
    }
    *path = ISO_CONFIG_FILE_PATH;
    return true;
}

int unmount_config_iso()
{
    return unmount("/mnt", 0);
}
#endif

static void set_rlimits(const char *rlimits)
{
    unsigned long long int lim_id, lim_cur, lim_max;
    struct rlimit rlim;
    char *item = (char *)rlimits;

    while (1) {
        lim_id = lim_cur = lim_max = ULLONG_MAX;

        lim_id = strtoull(item, &item, 10);
        if (lim_id == ULLONG_MAX) {
            printf("Invalid rlimit ID\n");
            break;
        }

        item++;
        lim_cur = strtoull(item, &item, 10);
        item++;
        lim_max = strtoull(item, &item, 10);

        rlim.rlim_cur = lim_cur;
        rlim.rlim_max = lim_max;
        if (setrlimit(lim_id, &rlim) != 0) {
            printf("Error setting rlimit for ID=%lld\n", lim_id);
        }

        if (*item != '\0') {
            item++;
        } else {
            break;
        }
    }
}

#ifdef SEV
/*
 * The LUKS passphrase is obtained from a KBS attestation server, complete an
 * SNP attestation to get the passphrase.
 */
static char *get_luks_passphrase(int *pass_len)
{
    int fd, ret, num_tokens, wid_found, url_found, tee_found, tee_data_found;
    uint64_t dev_size, tc_size;
    char wid[256], url[256], *tc_json, *tok_start, *tok_end;
    char footer[KRUN_FOOTER_LEN], tee[256], tee_data[256], *return_str;
    jsmn_parser parser;
    jsmntok_t *tokens;
    size_t tok_size;

    return_str = NULL;

    /*
     * If a user registered the TEE config data disk with
     * krun_set_data_disk(), it would appear as /dev/vdb in the guest.
     * Mount this device and read the config.
     */
    if (mkdir("/dev", 0755) < 0 && errno != EEXIST) {
        perror("mkdir(/dev)");
        goto finish;
    }

    if (mount("devtmpfs", "/dev", "devtmpfs", MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(devtmpfs)");

        goto rmdir_dev;
    }

    fd = open("/dev/vda", O_RDONLY);
    if (fd < 0) {
        perror("open(/dev/vda)");

        goto umount_dev;
    }

    ret = ioctl(fd, BLKGETSIZE64, &dev_size);
    if (ret != 0) {
        perror("ioctl(BLKGETSIZE64)");

        goto close_dev;
    }

    if (lseek(fd, dev_size - KRUN_FOOTER_LEN, SEEK_SET) == -1) {
        perror("lseek(END - KRUN_FOOTER_LEN)");

        goto close_dev;
    }

    ret = read(fd, &footer[0], KRUN_FOOTER_LEN);
    if (ret != KRUN_FOOTER_LEN) {
        perror("read(KRUN_FOOTER_LEN)");

        goto close_dev;
    }

    if (memcmp(&footer[0], KRUN_MAGIC, 4) != 0) {
        printf("Couldn't find KRUN footer signature, falling back to SEV\n");
        return_str = sev_get_luks_passphrase(pass_len);

        goto close_dev;
    }

    tc_size = *(uint64_t *)&footer[4];

    if (lseek(fd, dev_size - tc_size - KRUN_FOOTER_LEN, SEEK_SET) == -1) {
        perror("lseek(END - tc_size - KRUN_FOOTER_LEN)");

        goto close_dev;
    }

    tc_json = malloc(tc_size + 1);
    if (tc_json == NULL) {
        perror("malloc(tc_size)");

        goto close_dev;
    }

    ret = read(fd, tc_json, tc_size);
    if (ret != tc_size) {
        perror("read(tc_size)");

        goto free_mem;
    }
    tc_json[tc_size] = '\0';

    /*
     * Parse the TEE config's workload_id and attestation_url field.
     */
    jsmn_init(&parser);

    tokens = (jsmntok_t *)malloc(sizeof(jsmntok_t) * MAX_TOKENS);
    if (tokens == NULL) {
        perror("malloc(jsmntok_t)");

        goto free_mem;
    }

    num_tokens =
        jsmn_parse(&parser, tc_json, strlen(tc_json), tokens, MAX_TOKENS);
    if (num_tokens < 0) {
        printf("Unable to allocate JSON tokens\n");

        goto free_mem;
    } else if (num_tokens < 1 || tokens[0].type != JSMN_OBJECT) {
        printf("Unable to find object in TEE configuration file\n");

        goto free_mem;
    }

    wid_found = url_found = tee_found = tee_data_found = 0;

    for (int i = 1; i < num_tokens - 1; ++i) {
        tok_start = tc_json + tokens[i + 1].start;
        tok_end = tc_json + tokens[i + 1].end;
        tok_size = tok_end - tok_start;
        if (!jsoneq(tc_json, &tokens[i], "workload_id")) {
            strncpy(wid, tok_start, tok_size);
            wid_found = 1;
        } else if (!jsoneq(tc_json, &tokens[i], "attestation_url")) {
            strncpy(url, tok_start, tok_size);
            url_found = 1;
        } else if (!jsoneq(tc_json, &tokens[i], "tee")) {
            strncpy(tee, tok_start, tok_size);
            tee_found = 1;
        } else if (!jsoneq(tc_json, &tokens[i], "tee_data")) {
            strncpy(tee_data, tok_start, tok_size);
            tee_data_found = 1;
        }
    }

    if (!wid_found) {
        printf("Unable to find attestation workload ID\n");

        goto free_mem;
    } else if (!url_found) {
        printf("Unable to find attestation server URL\n");

        goto free_mem;
    } else if (!tee_found) {
        printf("Unable to find TEE generation server URL\n");

        goto free_mem;
    }

    if (strcmp(tee, "snp") == 0) {
        if (tee_data_found == 0) {
            printf("Unable to find SNP generation\n");
            goto free_mem;
        }

        return_str = snp_get_luks_passphrase(url, wid, tee_data, pass_len);
    } else if (strcmp(tee, "sev") == 0) {
        return_str = sev_get_luks_passphrase(pass_len);
    }

free_mem:
    free(tc_json);

close_dev:
    close(fd);

umount_dev:
    umount("/dev");

rmdir_dev:
    rmdir("/dev");

finish:
    return return_str;
}

static char *snp_get_luks_passphrase(char *url, char *wid, char *tee_data,
                                     int *pass_len)
{
    char *pass;

    pass = (char *)malloc(MAX_PASS_SIZE);
    if (pass == NULL) {
        return NULL;
    }

    if (snp_attest(pass, url, wid, tee_data) == 0) {
        *pass_len = strlen(pass);
        return pass;
    }

    free(pass);

    return NULL;
}

static char *sev_get_luks_passphrase(int *pass_len)
{
    char *pass = NULL;
    int len;
    int fd;

    pass = getenv("KRUN_PASS");
    if (pass) {
        *pass_len = strnlen(pass, MAX_PASS_SIZE);
        return pass;
    }
    if (mkdir("/sfs", 0755) < 0 && errno != EEXIST) {
        perror("mkdir(/sfs)");
        return NULL;
    }

    if (mount("securityfs", "/sfs", "securityfs",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/sfs)");
        goto cleanup_dir;
    }

    fd = open(CMDLINE_SECRET_PATH, O_RDONLY);
    if (fd < 0) {
        goto cleanup_sfs;
    }

    pass = malloc(MAX_PASS_SIZE);
    if (!pass) {
        goto cleanup_fd;
    }

    if ((len = read(fd, pass, MAX_PASS_SIZE)) < 0) {
        free(pass);
        pass = NULL;
    } else {
        *pass_len = len;
        unlink(CMDLINE_SECRET_PATH);
    }

cleanup_fd:
    close(fd);
cleanup_sfs:
    umount("/sfs");
cleanup_dir:
    rmdir("/sfs");

    return pass;
}

static int chroot_luks()
{
    char *pass;
    int pass_len;
    int pid;
    int pipefd[2];
    int wstatus;

    pass = get_luks_passphrase(&pass_len);
    if (!pass) {
        printf("Couldn't find LUKS passphrase\n");
        return -1;
    }

    printf("Unlocking LUKS root filesystem\n");

    if (mount("proc", "/proc", "proc",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/proc)");
        return -1;
    }

    pipe(pipefd);

    pid = fork();
    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], 0);
        close(pipefd[0]);

        if (execl("/sbin/cryptsetup", "cryptsetup", "open", "/dev/vda",
                  "luksroot", "-", NULL) < 0) {
            perror("execl");
            return -1;
        }
    } else {
        write(pipefd[1], pass, strnlen(pass, pass_len));
        close(pipefd[1]);
        waitpid(pid, &wstatus, 0);
    }

    memset(pass, 0, pass_len);

    printf("Mounting LUKS root filesystem\n");

    if (mount("/dev/mapper/luksroot", "/luksroot", "ext4", 0, NULL) < 0) {
        perror("mount(/luksroot)");
        return -1;
    }

    chdir("/luksroot");

    if (mount(".", "/", NULL, MS_MOVE, NULL)) {
        perror("remount root");
        return -1;
    }
    chroot(".");

    return 0;
}
#endif

static int mount_filesystems()
{
#if __linux__
    char *const DIRS_LEVEL1[] = {"/dev", "/proc", "/sys"};
    char *const DIRS_LEVEL2[] = {"/dev/pts", "/dev/shm"};
    int i;

    for (i = 0; i < 3; ++i) {
        if (mkdir(DIRS_LEVEL1[i], 0755) < 0 && errno != EEXIST) {
            printf("Error creating directory (%s)\n", DIRS_LEVEL1[i]);
            return -1;
        }
    }

    if (mount("devtmpfs", "/dev", "devtmpfs", MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/dev)");
        return -1;
    }

    /*
     * Best effort loosen /dev/kvm permissions to allow nested virtualization by
     * unprivileged processes inside the microVM (usually a single purpose
     * environment). Log errors but don't log ENOENT since the guest kernel may
     * not support KVM or nested virtualization might not be enabled.
     */
    if (chmod("/dev/kvm", 0666) < 0 && errno != ENOENT) {
        perror("chmod(/dev/kvm)");
    }

    if (mount("proc", "/proc", "proc",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/proc)");
        return -1;
    }

    if (mount("sysfs", "/sys", "sysfs",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/sys)");
        return -1;
    }

    if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/sys/fs/cgroup)");
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        if (mkdir(DIRS_LEVEL2[i], 0755) < 0 && errno != EEXIST) {
            printf("Error creating directory (%s)\n", DIRS_LEVEL2[i]);
            return -1;
        }
    }

    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/dev/pts)");
        return -1;
    }

    if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_RELATIME,
              NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/dev/shm)");
        return -1;
    }

    /* May fail if already exists and that's fine. */
    symlink("/proc/self/fd", "/dev/fd");
#endif
    return 0;
}

/*
 * hexToDigit, Utf32toUtf8 and parts of unescape_string are taken from libyajl:
 *
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static void hexToDigit(unsigned int *val, const unsigned char *hex)
{
    unsigned int i;
    for (i = 0; i < 4; i++) {
        unsigned char c = hex[i];
        if (c >= 'A')
            c = (c & ~0x20) - 7;
        c -= '0';
        *val = (*val << 4) | c;
    }
}

static void Utf32toUtf8(unsigned int codepoint, char *utf8Buf)
{
    if (codepoint < 0x80) {
        utf8Buf[0] = (char)codepoint;
        utf8Buf[1] = 0;
    } else if (codepoint < 0x0800) {
        utf8Buf[0] = (char)((codepoint >> 6) | 0xC0);
        utf8Buf[1] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[2] = 0;
    } else if (codepoint < 0x10000) {
        utf8Buf[0] = (char)((codepoint >> 12) | 0xE0);
        utf8Buf[1] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[2] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[3] = 0;
    } else if (codepoint < 0x200000) {
        utf8Buf[0] = (char)((codepoint >> 18) | 0xF0);
        utf8Buf[1] = (char)(((codepoint >> 12) & 0x3F) | 0x80);
        utf8Buf[2] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[3] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[4] = 0;
    } else {
        utf8Buf[0] = '?';
        utf8Buf[1] = 0;
    }
}

/* Do not worry about invalid JSON, it was already parsed by jsmn.  */
static void unescape_string(char *string, int len)
{
    unsigned char *val = (unsigned char *)string;
    unsigned char *end;
    int i = 0;

    end = val + len;
    while (val < end) {
        if (*val != '\\') {
            string[i++] = *val++;
            continue;
        }
        switch (*++val) {
        case 'n':
            string[i++] = '\n';
            val++;
            break;
        case 't':
            string[i++] = '\t';
            val++;
            break;
        case 'r':
            string[i++] = '\r';
            val++;
            break;
        case 'b':
            string[i++] = '\b';
            val++;
            break;
        case 'f':
            string[i++] = '\f';
            val++;
            break;
        case '\\':
            string[i++] = '\\';
            val++;
            break;
        case '\"':
            string[i++] = '\"';
            val++;
            break;
        case '/':
            string[i++] = '/';
            val++;
            break;
        case 'u': {
            const char *unescaped = "?";
            char utf8Buf[5];
            unsigned int codepoint = 0;
            hexToDigit(&codepoint, val++);
            val += 3;
            /* check if this is a surrogate */
            if ((codepoint & 0xFC00) == 0xD800) {
                val++;
                if (val[0] == '\\' && val[1] == 'u') {
                    unsigned int surrogate = 0;
                    hexToDigit(&surrogate, val + 2);
                    codepoint = (((codepoint & 0x3F) << 10) |
                                 ((((codepoint >> 6) & 0xF) + 1) << 16) |
                                 (surrogate & 0x3FF));
                    val += 5;
                } else {
                    unescaped = "?";
                    break;
                }
            }

            Utf32toUtf8(codepoint, utf8Buf);
            unescaped = utf8Buf;

            if (codepoint == 0) {
                memcpy(&string[i++], unescaped, 1);
                continue;
            }
            memcpy(&string[i], unescaped, (unsigned int)strlen(unescaped));
            break;
        }
        }
    }
    string[i] = '\0';
}

static void config_parse_env(char *data, jsmntok_t *token)
{
    jsmntok_t *tenv;
    char *env, *env_val;
    int len;
    int i;

    for (i = 0; i < token->size; i++) {
        tenv = &token[i + 1];

        env = data + tenv->start;
        len = tenv->end - tenv->start;

        unescape_string(env, len);

        env_val = strstr(env, "=");
        if (!env_val) {
            continue;
        }

        env[len] = '\0';
        *env_val = '\0';
        env_val++;

        if ((strcmp(env, "HOME") == 0) || (strcmp(env, "TERM") == 0)) {
            setenv(env, env_val, 1);
        } else {
            setenv(env, env_val, 0);
        }
    }
}

static char **config_parse_args(char *data, jsmntok_t *token)
{
    jsmntok_t *targ;
    char *arg, *value;
    char **argv;
    int len;
    int i;
    const int n_args = token->size;

    argv = malloc((n_args + 1) * sizeof(char *));
    if (!argv) {
        perror("malloc(config_parse_args)");
        return NULL;
    }

    for (i = 0; i < n_args; i++) {
        targ = &token[i + 1];

        value = data + targ->start;
        len = targ->end - targ->start;

        arg = malloc(len + 1);
        if (!arg) {
            perror("malloc(config_parse_args arg)");
            while (--i >= 0)
                free(argv[i]);
            free(argv);
            return NULL;
        }
        memcpy(arg, value, len);
        arg[len] = '\0';

        unescape_string(arg, len);

        argv[i] = arg;
    }

    if (i == 0) {
        free(argv);
        argv = NULL;
    } else {
        argv[i] = NULL;
    }

    return argv;
}

static char *config_parse_string(char *data, jsmntok_t *token)
{
    char *string;
    char *val;
    int len;

    val = data + token->start;
    len = token->end - token->start;
    if (!len) {
        return NULL;
    }

    string = malloc(len + 1);

    if (!string) {
        return NULL;
    }
    memcpy(string, val, len);
    string[len] = '\0';

    unescape_string(string, len);

    return string;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncasecmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

char **concat_entrypoint_argv(char **entrypoint, char **config_argv)
{
    char **argv;
    int i, j;
    int n_args = 0;

    for (i = 0; entrypoint[i]; i++)
        n_args++;
    for (j = 0; config_argv[j]; j++)
        n_args++;

    argv = malloc((n_args + 1) * sizeof(char *));
    if (!argv) {
        perror("malloc(concat_entrypoint_argv)");
        return NULL;
    }

    for (i = 0; entrypoint[i]; i++) {
        argv[i] = entrypoint[i];
    }

    for (j = 0; config_argv[j]; i++, j++) {
        argv[i] = config_argv[j];
    }

    argv[i] = NULL;

    return argv;
}

static int config_parse_file(char ***argv, char **workdir,
                             const char *config_file)
{
    jsmn_parser parser;
    jsmntok_t *tokens;
    struct stat stat;
    char *data;
    off_t data_len;
    char **config_argv;
    char **entrypoint;
    int parsed_env, parsed_workdir, parsed_args, parsed_entrypoint;
    int num_tokens;
    int ret = -1;
    int fd;
    int i;

    fd = open(config_file, O_RDONLY);
    if (fd < 0) {
        return ret;
    }

    if (fstat(fd, &stat) != 0) {
        perror("Couldn't stat config file");
        goto cleanup_fd;
    }

    data_len = stat.st_size;
    data = malloc(data_len);
    if (!data) {
        perror("Couldn't allocate memory");
        goto cleanup_fd;
    }

    if (read(fd, data, data_len) < 0) {
        perror("Error reading config file");
        goto cleanup_data;
    }

    tokens = malloc(MAX_TOKENS * sizeof(jsmntok_t));
    if (!tokens) {
        perror("Couldn't allocate memory");
        goto cleanup_data;
    }

    jsmn_init(&parser);
    num_tokens = jsmn_parse(&parser, data, data_len, tokens, MAX_TOKENS);
    if (num_tokens < 0) {
        printf("Error parsing config file\n");
        goto cleanup_tokens;
    }

    if (num_tokens < 1 || tokens[0].type != JSMN_OBJECT) {
        printf("Couldn't find object in config file\n");
        goto cleanup_tokens;
    }

    config_argv = NULL;
    entrypoint = NULL;
    parsed_env = parsed_workdir = parsed_args = parsed_entrypoint = 0;

    for (i = 1; i < num_tokens && (!parsed_env || !parsed_args ||
                                   !parsed_workdir || !parsed_entrypoint);
         i++) {
        if (!parsed_env && jsoneq(data, &tokens[i], "Env") == 0 &&
            (i + 1) < num_tokens && tokens[i + 1].type == JSMN_ARRAY) {
            config_parse_env(data, &tokens[i + 1]);
            parsed_env = 1;
        }

        if (!parsed_args && jsoneq(data, &tokens[i], "args") == 0 &&
            (i + 1) < num_tokens) {
            config_argv = config_parse_args(data, &tokens[i + 1]);
            parsed_args = 1;
        }

        if (!parsed_args && jsoneq(data, &tokens[i], "Cmd") == 0 &&
            (i + 1) < num_tokens) {
            config_argv = config_parse_args(data, &tokens[i + 1]);
            parsed_args = 1;
        }

        if (!parsed_workdir && jsoneq(data, &tokens[i], "WorkingDir") == 0 &&
            (i + 1) < num_tokens) {
            *workdir = config_parse_string(data, &tokens[i + 1]);
            parsed_workdir = 1;
        }

        if (!parsed_workdir && jsoneq(data, &tokens[i], "Cwd") == 0 &&
            (i + 1) < num_tokens) {
            *workdir = config_parse_string(data, &tokens[i + 1]);
            parsed_workdir = 1;
        }

        if (!parsed_entrypoint && jsoneq(data, &tokens[i], "Entrypoint") == 0 &&
            (i + 1) < num_tokens) {
            entrypoint = config_parse_args(data, &tokens[i + 1]);
            parsed_entrypoint = 1;
        }
    }

    if (config_argv && entrypoint) {
        *argv = concat_entrypoint_argv(entrypoint, config_argv);
    } else {
        *argv = config_argv;
    }

    ret = 0;

cleanup_tokens:
    free(tokens);
cleanup_data:
    free(data);
cleanup_fd:
    close(fd);

    return ret;
}

#ifdef __TIMESYNC__

#define TSYNC_PORT 123
#define BUFSIZE 8
#define NANOS_IN_SECOND 1000000000
/* Set clock if delta is bigger than 100ms */
#define DELTA_SYNC 100000000

void clock_worker()
{
    int sockfd, n;
    struct sockaddr_vm serveraddr;
    char buf[BUFSIZE];
    struct timespec gtime;
    struct timespec htime;
    uint64_t gtime_ns;
    uint64_t htime_ns;

    sockfd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Couldn't create timesync socket");
        return;
    }

    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.svm_family = AF_VSOCK;
    serveraddr.svm_port = TSYNC_PORT;
    serveraddr.svm_cid = 3;

    bzero(buf, BUFSIZE);

    n = bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (n < 0) {
        printf("Couldn't bind timesync socket\n");
        return;
    }

    while (1) {
        n = recv(sockfd, buf, BUFSIZE, 0);
        if (n < 0) {
            perror("Error in timesync recv");
            return;
        } else if (n != 8) {
            printf("Ignoring bogus timesync packet\n");
            continue;
        }

        htime_ns = *(uint64_t *)&buf[0];
        clock_gettime(CLOCK_REALTIME, &gtime);
        gtime_ns = gtime.tv_sec * NANOS_IN_SECOND;
        gtime_ns += gtime.tv_nsec;

        if (llabs(htime_ns - gtime_ns) > DELTA_SYNC) {
            htime.tv_sec = htime_ns / NANOS_IN_SECOND;
            htime.tv_nsec = htime_ns % NANOS_IN_SECOND;
            clock_settime(CLOCK_REALTIME, &htime);
        }
    }
}
#endif

int reopen_fd(int fd, char *path, int flags)
{
    int newfd = open(path, flags);
    if (newfd < 0) {
        printf("Failed to open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    close(fd);
    if (dup2(newfd, fd) < 0) {
        perror("dup2");
        close(newfd);
        return -1;
    }
    close(newfd);
    return 0;
}

int setup_redirects()
{
    DIR *ports_dir = opendir("/sys/class/virtio-ports");
    if (ports_dir == NULL) {
        printf("Unable to open ports directory!\n");
        return -4;
    }

    char path[2048];
    char name_buf[1024];

    struct dirent *entry = NULL;
    while ((entry = readdir(ports_dir))) {
        char *port_identifier = entry->d_name;
        int result_len =
            snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name",
                     port_identifier);

        // result was truncated
        if (result_len > sizeof(name_buf) - 1) {
            printf("Path buffer too small");
            return -1;
        }

        FILE *port_name_file = fopen(path, "r");
        if (port_name_file == NULL) {
            continue;
        }

        char *port_name = fgets(name_buf, sizeof(name_buf), port_name_file);
        fclose(port_name_file);

        if (port_name != NULL && strcmp(port_name, "krun-stdin\n") == 0) {
            // if previous snprintf didn't fail, this one cannot fail either
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDIN_FILENO, path, O_RDONLY);
        } else if (port_name != NULL &&
                   strcmp(port_name, "krun-stdout\n") == 0) {
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDOUT_FILENO, path, O_WRONLY);
        } else if (port_name != NULL &&
                   strcmp(port_name, "krun-stderr\n") == 0) {
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDERR_FILENO, path, O_WRONLY);
        }
    }

    closedir(ports_dir);
    return 0;
}

int is_virtiofs(const char *path)
{
    struct statfs fs;

    if (statfs(path, &fs) != 0) {
        perror("statfs");
        return -1;
    }

    // virtiofs magic number: 0x65735546
    return (fs.f_type == 0x65735546) ? 1 : 0;
}

void set_exit_code(int code)
{
    int fd;
    int ret;
    int virtiofs_check;

    // Only use the ioctl if virtiofs is used for root filesystem
    virtiofs_check = is_virtiofs("/");
    if (virtiofs_check < 0) {
        printf("Warning: Could not determine filesystem type for root\n");
    }

    if (virtiofs_check == 0) {
        // Root filesystem is not virtiofs, skip the ioctl
        return;
    }

    fd = open("/", O_RDONLY);
    if (fd < 0) {
        perror("Couldn't open root filesystem to report exit code");
        return;
    }

    ret = ioctl(fd, KRUN_EXIT_CODE_IOCTL, code);
    if (ret < 0) {
        perror("Error using the ioctl to set the exit code");
    }

    close(fd);
}

#if __linux__
int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data)
{
    FILE *f;
    char line[129];
    int mount_status = -1;

    if (fstype) {
        return mount(source, target, fstype, mountflags, data);
    }

    f = fopen("/proc/filesystems", "r");
    if (f == NULL) {
        perror("fopen(/proc/filesystems)");
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char fstype[sizeof(line)];
        if (!strncmp(line, "nodev", 5)) {
            continue;
        }
        if (sscanf(line, "%128s\n", fstype) != 1) {
            continue;
        }

        mount_status = mount(source, target, fstype, mountflags, data);
        if (mount_status == 0) {
            break;
        }
    }
    fclose(f);

    return mount_status;
}
#endif

char *clone_str(const char *str)
{
    if (str == NULL) {
        return NULL;
    }
    return strdup(str);
}

#if __linux__
static bool tsi_enabled()
{
    const char *const option = "tsi_hijack";
    bool enabled = false;
    char *cmdline = NULL;
    size_t cmdline_length = 0;
    FILE *f;
    const char *const delimiters = " \n";
    char *token;

    f = fopen("/proc/cmdline", "r");
    if (f == NULL) {
        perror("fopen(/proc/cmdline)");
        return false;
    }

    if (getline(&cmdline, &cmdline_length, f) < 0) {
        perror("getline(/proc/cmdline)");
        fclose(f);
        goto cleanup;
    }
    fclose(f);

    token = strtok(cmdline, delimiters);
    while (token != NULL) {
        if (strcmp(token, "--") == 0) {
            break;
        }
        if (strcmp(token, option) == 0) {
            enabled = true;
            break;
        }
        token = strtok(NULL, delimiters);
    }

cleanup:
    free(cmdline);

    return enabled;
}

static int enable_dummy_interface()
{
    // See https://www.man7.org/linux/man-pages/man7/netdevice.7.html

    const char *const name = "dummy0";
    struct ifreq ifr;
    int sockfd;
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    struct sockaddr_in *netmask = (struct sockaddr_in *)&ifr.ifr_netmask;
    int result = -1;

    if (snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name) >= IFNAMSIZ) {
        printf("dummy interface name too long\n");
        return -1;
    }

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("dummy interface socket");
        return -1;
    }

    ifr.ifr_flags = IFF_UP;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        if (errno == ENODEV) {
            // Most likely not enabled in the kernel, ignore quietly
            result = 0;
            goto close_socket;
        }
        perror("dummy interface up");
        goto close_socket;
    }

    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, "203.0.113.1", &addr->sin_addr) <= 0) {
        printf("inet_pton address conversion failed\n");
        goto close_socket;
    }
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("dummy interface address");
        goto close_socket;
    }

    netmask->sin_family = AF_INET;
    if (inet_pton(AF_INET, "255.255.255.0", &netmask->sin_addr) <= 0) {
        printf("inet_pton netmask conversion failed\n");
        goto close_socket;
    }
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("dummy interface mask");
        goto close_socket;
    }

    result = 0;

close_socket:
    close(sockfd);
    return result;
}
#endif

int main(int argc, char **argv)
{
    struct ifreq ifr;
    int sockfd;
    int status;
    int saved_errno;
    bool init_pid1 = false;
    char localhost[] = "localhost\0";
    char *hostname;
    char *krun_home;
    char *krun_term;
    char *krun_init;
#if __linux__
    char *krun_dhcp;
    int fd;
    char *krun_root;
    char *krun_root_fstype;
    char *krun_root_options;
#endif
    char *env_init_pid1;
    char *config_workdir, *env_workdir;
    char *rlimits;
    char **config_argv, **exec_argv;
    const char *config_file;
#if __FreeBSD__
    bool config_file_mounted = false;

    open_console();
#endif

#ifdef TDX
    if (mkdir("/tmp", 0755) < 0 && errno != EEXIST) {
        perror("mkdir(/tmp)");
        exit(-1);
    }
    if (mkdir("/tmp/vda", 0755) < 0 && errno != EEXIST) {
        perror("mkdir(/tmp/vda)");
        exit(-1);
    }
    if (mount("/dev/vda", "/tmp/vda", "ext4", MS_RELATIME, NULL) < 0) {
        perror("mount(/dev/vda)");
        exit(-1);
    }
    chdir("/tmp/vda");
    if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
        perror("remount root");
        exit(-1);
    }
    chroot(".");

#endif

#ifdef SEV
    if (chroot_luks() < 0) {
        printf("Couldn't switch to LUKS volume, bailing out\n");
        exit(-1);
    }
#endif
    if (mount_filesystems() < 0) {
        printf("Couldn't mount filesystems, bailing out\n");
        exit(-2);
    }

#if __linux__
    krun_root = clone_str(getenv("KRUN_BLOCK_ROOT_DEVICE"));
    if (krun_root) {
        if (mkdir("/newroot", 0755) < 0 && errno != EEXIST) {
            perror("mkdir(/newroot)");
            exit(-1);
        }

        krun_root_fstype = clone_str(getenv("KRUN_BLOCK_ROOT_FSTYPE"));
        krun_root_options = clone_str(getenv("KRUN_BLOCK_ROOT_OPTIONS"));

        if (try_mount(krun_root, "/newroot", krun_root_fstype, 0,
                      krun_root_options) < 0) {
            perror("mount KRUN_BLOCK_ROOT_DEVICE");
            exit(-1);
        }
        free(krun_root);
        free(krun_root_fstype);
        free(krun_root_options);

        chdir("/newroot");

        if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
            perror("remount root");
            exit(-1);
        }
        chroot(".");

        // we must mount filesystems again after chrooting
        if (mount_filesystems() < 0) {
            printf("Couldn't mount filesystems, bailing out\n");
            exit(-2);
        }
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_SHARED, NULL) < 0) {
        perror("Couldn't set shared propagation on the root mount");
        exit(-1);
    }
#endif

    setsid();
    ioctl(0, TIOCSCTTY, 1);

#if __FreeBSD__
    setlogin("root");
#endif

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd >= 0) {
        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sockfd, SIOCSIFFLAGS, &ifr);

#if __linux__
        krun_dhcp = getenv("KRUN_DHCP");
        if (krun_dhcp && strcmp(krun_dhcp, "1") == 0) {
            memset(&ifr, 0, sizeof ifr);
            strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
            if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == 0) {
                /* eth0 exists, bring it up first */
                ifr.ifr_flags |= IFF_UP;
                ioctl(sockfd, SIOCSIFFLAGS, &ifr);

                /* Configure eth0 with DHCP */
                if (do_dhcp("eth0") != 0) {
                    printf("Warning: DHCP configuration for eth0 failed\n");
                }
            }
        }
#endif

        close(sockfd);
    }

#if __linux__
    if (tsi_enabled()) {
        if (enable_dummy_interface() < 0) {
            printf("Warning: Couldn't enable dummy interface\n");
        }
    }
#endif

    config_argv = NULL;
    config_workdir = NULL;

    config_file = getenv("KRUN_CONFIG");

#if __FreeBSD__
    if (!config_file) {
        config_file_mounted = config_file_from_iso(&config_file);
    }
#endif

    if (!config_file) {
        config_file = CONFIG_FILE_PATH;
    }

    config_parse_file(&config_argv, &config_workdir, config_file);

#if __FreeBSD__
    if (config_file_mounted) {
        unmount_config_iso();
    }
#endif

    krun_home = getenv("KRUN_HOME");
    if (krun_home) {
        setenv("HOME", krun_home, 1);
    }

    krun_term = getenv("KRUN_TERM");
    if (krun_term) {
        setenv("TERM", krun_term, 1);
    }

    hostname = getenv("HOSTNAME");
    if (hostname) {
        sethostname(hostname, strlen(hostname));
    } else {
        sethostname(&localhost[0], strlen(localhost));
    }

    rlimits = getenv("KRUN_RLIMITS");
    if (rlimits) {
        set_rlimits(rlimits);
    }

    env_workdir = getenv("KRUN_WORKDIR");
    if (env_workdir) {
        chdir(env_workdir);
    } else if (config_workdir) {
        chdir(config_workdir);
    }

    exec_argv = argv;
    krun_init = getenv("KRUN_INIT");
    if (krun_init) {
        exec_argv[0] = clone_str(krun_init);
    } else if (config_argv) {
        exec_argv = config_argv;
    } else {
        exec_argv[0] = &DEFAULT_KRUN_INIT[0];
    }

    env_init_pid1 = getenv("KRUN_INIT_PID1");
    if (env_init_pid1 && *env_init_pid1 == '1') {
        init_pid1 = true;
    }

#ifdef __TIMESYNC__
    if (fork() == 0) {
        clock_worker();
        _exit(1);
    }
#endif

    if (init_pid1) {
        goto exec_init;
    }

    // We need to fork ourselves, because pid 1 cannot doesn't receive SIGINT
    // signal
    int child = fork();
    if (child < 0) {
        perror("fork");
        set_exit_code(125);
        exit(125);
    }
    if (child == 0) { // child
    exec_init:
#if __FreeBSD__
        open_console();
#else
        if (setup_redirects() < 0) {
            exit(125);
        }
#endif
        if (execvp(exec_argv[0], exec_argv) < 0) {
            saved_errno = errno;
            printf("Couldn't execute '%s' inside the vm: %s\n", exec_argv[0],
                   strerror(errno));
            // Use the same exit code as chroot and podman do.
            if (saved_errno == ENOENT) {
                exit(127);
            } else {
                exit(126);
            }
        }
    } else { // parent
        // Wait until the workload's entrypoint has exited, ignoring any other
        // children.
        while (waitpid(-1, &status, 0) != child) {
            // Not the first child, ignore it.
        };

        // The workload's entrypoint has exited, record its exit code and exit
        // ourselves.
        if (WIFEXITED(status)) {
            set_exit_code(WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            set_exit_code(WTERMSIG(status) + 128);
        }

        sync();
#if __linux__
        reboot(LINUX_REBOOT_CMD_RESTART);
#endif
    }

    return 0;
}
