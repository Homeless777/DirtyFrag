#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <asm/cpufeature.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);
typedef int  (*register_kprobe_t)(struct kprobe *p);
typedef void (*unregister_kprobe_t)(struct kprobe *p);

static insn_patch_t insn_patch_text;

static __nocfi void patch_fn_ret_zero(void *fn)
{
    u32  insn  = *(u32 *)fn;
    int  skip  = 0;
    bool pac_a = false, pac_b = false;
    void *addrs[2];
    u32   insns[2];

    while (skip < 2) {
        switch (insn) {
        case 0xD503233F: pac_a = true; goto skip_insn;
        case 0xD503237F: pac_b = true; goto skip_insn;
        case 0xD503241F:
        case 0xD503245F:
        case 0xD503249F:
        case 0xD50324DF:
        skip_insn:
            insn = *(u32 *)((u8 *)fn + ++skip * 4);
            continue;
        }
        break;
    }

    addrs[0] = (u8 *)fn + skip * 4;
    addrs[1] = (u8 *)fn + skip * 4 + 4;
    insns[0] = 0xD2800000;
    insns[1] = (pac_b && system_supports_address_auth()) ? 0xD65F0FFF :
               (pac_a && system_supports_address_auth()) ? 0xD65F0BFF :
                                                           0xD65F03C0;

    if (insn_patch_text(addrs, insns, 2))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

/*
 * Use a kprobe on printk (always exported) to get a kernel address,
 * then scan nearby memory for kallsyms_lookup_name string and function.
 * This avoids any problematic RELA relocations.
 */
static kallsyms_lookup_name_t find_kallsyms_lookup_name(void)
{
    /* printk is always exported — use it as our anchor */
    unsigned long anchor = (unsigned long)__kmalloc;
    unsigned long base, end;
    unsigned long *ptr;

    /* Kernel text is typically within 128MB of any exported symbol */
    base = anchor & ~0x7FFFFFFUL;
    end  = base + 0x8000000UL;

    /* Scan for kallsyms_lookup_name by looking for its name string
     * and correlating with the ksymtab entries */
    for (ptr = (unsigned long *)base; ptr < (unsigned long *)end; ptr++) {
        /* Look for a pointer that could be kallsyms_lookup_name:
         * it must be in kernel text range and aligned */
        if ((*ptr & 0xFFFFFFFF00000000UL) == (anchor & 0xFFFFFFFF00000000UL) &&
            (*ptr & 0xFFF) == 0) {
            /* Check if this looks like a function by verifying
             * the first instruction is a valid aarch64 prologue */
            u32 first_insn = *(u32 *)(void *)*ptr;
            if (first_insn == 0xD503233F || /* PACIASP */
                first_insn == 0xD503237F || /* PACIBSP */
                first_insn == 0xD503241F || /* BTI     */
                (first_insn & 0xFFC003FF) == 0xD10003FF) { /* SUB SP,SP,# */
                /* Validate by checking the name nearby */
                char *p = (char *)ptr - 64;
                int i;
                for (i = 0; i < 128; i++, p++) {
                    if (!memcmp(p, "kallsyms_lookup_name", 20)) {
                        return (kallsyms_lookup_name_t)*ptr;
                    }
                }
            }
        }
    }
    return NULL;
}

static __nocfi int __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    module_kallsyms_lookup_name_t mkln;
    void *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;

    static const char sh[] = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/df.root/bootstrap";
    static char cmd[512];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd), "touch /dev/dfm0; exec %s", bootstrap);

    get_addr = find_kallsyms_lookup_name();
    if (!get_addr) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    pr_info("dfroot: kallsyms_lookup_name at %px\n", get_addr);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    mkln = (module_kallsyms_lookup_name_t)get_addr("module_kallsyms_lookup_name");

    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    oplus_exe_fn = (void *)(mkln ? mkln("oplus_exe_block_ret_handler") : 0);
    if (!oplus_exe_fn)
        pr_err("dfroot: oplus_exe_block_ret_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_exe_fn);
        pr_info("dfroot: oplus_exe_block_ret_handler patched\n");
    }

    oplus_root_fn = (void *)(mkln ? mkln("oplus_root_check_post_handler") : 0);
    if (!oplus_root_fn)
        pr_err("dfroot: oplus_root_check_post_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_root_fn);
        pr_info("dfroot: oplus_root_check_post_handler patched\n");
    }

    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }

    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

    return -ENODEV;
}

module_init(dfroot_init);