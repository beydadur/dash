#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("psvis - Process Tree Visualizer");

static int pid = 1; // Varsayılan PID
module_param(pid, int, 0444);
MODULE_PARM_DESC(pid, "The PID of the root process");

static void print_process_tree(struct seq_file *m, struct task_struct *task, int depth) {
    struct list_head *list;
    struct task_struct *child;

    // Mevcut süreci yazdır
    seq_printf(m, "%*sPID: %d | Command: %s\n", depth * 2, "", task->pid, task->comm);

    // Çocuk süreçleri döngüyle gezin
    list_for_each(list, &task->children) {
        child = list_entry(list, struct task_struct, sibling);
        print_process_tree(m, child, depth + 1);
    }
}

static int psvis_proc_show(struct seq_file *m, void *v) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        seq_printf(m, "Invalid PID: %d\n", pid);
        return 0;
    }

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        seq_printf(m, "Could not find task for PID: %d\n", pid);
        return 0;
    }

    seq_printf(m, "Process Tree (PID: %d):\n", pid);
    print_process_tree(m, task, 0);
    return 0;
}

static int psvis_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, psvis_proc_show, NULL);
}

// Yeni `proc_ops` yapısı
static const struct proc_ops psvis_fops = {
    .proc_open = psvis_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init psvis_init(void) {
    proc_create("psvis", 0, NULL, &psvis_fops);
    printk(KERN_INFO "psvis module loaded. PID: %d\n", pid);
    return 0;
}

static void __exit psvis_exit(void) {
    remove_proc_entry("psvis", NULL);
    printk(KERN_INFO "psvis module unloaded.\n");
}

module_init(psvis_init);
module_exit(psvis_exit);

