/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 Admirepowered. All Rights Reserved.
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <kpm_utils.h>
#include <kpm_hook_utils.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Admirepowered");
KPM_DESCRIPTION("injector for zygisk");


const char *margs=0;
enum hook_type hook_type= NONE;

long do_fork(struct pt_regs *regs, unsigned long clone_flags, unsigned long stack_start,
             unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr);
static inline void printInfo()
{
    pr_info("Kernel Version: %x\n", kver);
    pr_info("Kernel Patch Version: %x\n", kpver);
}

void before_openat_0(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    char buf[1024];
    compact_strncpy_from_user(buf, filename, sizeof(buf));

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    args->local.data0 = (uint64_t)task;

    pr_info("hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", task, pid,
            tgid, dfd, buf, flag, mode);
    if (pid==38){

        pr_info("zygote found , start inject");
        
    }
    
}
static long zygisk_fork_init(const char *args, const char *event, void *__user reserved)
{
    long ret = 0;
    margs = args;
    do_fork = (typeof(do_fork))kallsyms_lookup_name("do_fork");
    pr_info("kernel function do_fork addr: %llx\n", do_fork);
    printInfo();
    pr_info("HFR: initializing ...\n");
    hook_type = INLINE_CHAIN;
    err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
    if (err) {
        pr_err("hook openat error: %d\n", err);
        goto err;
    } else {
        pr_info("hook openat success\n");
        goto exit;
    }
err:
    ret = 1;
    pr_info("HFR: initializing failed!\n");
exit:
    return ret;
}


static inline bool hfr_control(bool enable)
{
    return true;
}

static long zygisk_control0(const char *args, char *__user out_msg, int outlen)
{
    if (args) {
        if (strncmp(args, "enable", 6) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(true) ? "HFR: enabled !" : "HFR: enable fail !");
        } else if (strncmp(args, "disable", 7) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(false) ? "HFR: disbaled !" : "HFR: disbale fail !");
        } else {
            pr_info("HFR: ctl error, args=%s\n", args);
            writeOutMsg(out_msg, &outlen, "HFR: ctl error !");
            return -1;
        }
    }
    return 0;
}

static long zygisk_exit(void *__user reserved)
{
    
    pr_info("HFR: Exiting ...\n");
    return 0;
}

KPM_INIT(zygisk_fork_init);
KPM_CTL0(zygisk_control0);
KPM_EXIT(zygisk_exit);
