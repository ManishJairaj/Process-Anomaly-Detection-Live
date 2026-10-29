#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define PROCESS_NAME_LEN 64

struct syscall_event
{
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __s32 syscall_id;
    char process_name[PROCESS_NAME_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct raw_syscall_context
{
    __u64 unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int collect_syscall(struct raw_syscall_context *ctx)
{
    struct syscall_event *event;
    struct task_struct *task;
    __u64 pid_tgid;
    __u64 uid_gid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xffffffff;
    event->syscall_id = ctx->id;

    task = (struct task_struct *)bpf_get_current_task();

    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(event->process_name,
                         sizeof(event->process_name));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
