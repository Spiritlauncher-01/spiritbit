// spiritbit.bpf.c - Spiritbit v4.4 Full Kernel Monitoring
// Expanded with multiple hooks for comprehensive coverage (Filesystem, Process, Network, etc.)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define SPIRITBIT_EVENT_VERSION 42

// Event Types
#define EVENT_OPENAT   1
#define EVENT_EXECVE   2
#define EVENT_RENAME   3
#define EVENT_UNLINK   4
#define EVENT_PTRACE   5
#define EVENT_IOURING  6
#define EVENT_CONNECT  7
#define EVENT_WRITE    8

// Main event structure passed to userspace
struct event {
    __u8  version;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 ts;
    char comm[16];
    char path[160];           // Increased size for full paths
    __u32 event_type;
    __u8  sensitive;
    __u8  write_attempt;
    __u8  truncated;          // Flag if path was too long
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);   // Controlled from config.h
} events SEC(".maps");

// Helper: Check sensitive paths
static bool is_sensitive(const char *p) {
    if (!p) return false;
    if (bpf_strncmp(p, 5, "/etc/") == 0) return true;
    if (bpf_strncmp(p, 6, "/root/") == 0) return true;
    if (bpf_strncmp(p, 5, "/.ssh") == 0) return true;
    if (bpf_strncmp(p, 11, "/etc/shadow") == 0) return true;
    if (bpf_strncmp(p, 13, "/etc/passwd") == 0) return true;
    if (bpf_strncmp(p, 8, "/bin/su") == 0) return true;
    return false;
}

// ====================== HOOKS ======================

// 1. File Open Monitoring
SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_OPENAT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)ctx->args[1]);
    e->sensitive = is_sensitive(e->path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 2. Process Execution Monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_EXECVE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)ctx->args[0]);
    e->sensitive = is_sensitive(e->path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. File Rename Monitoring
SEC("tracepoint/syscalls/sys_enter_renameat")
int on_rename(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_RENAME;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)ctx->args[1]);
    e->sensitive = is_sensitive(e->path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 4. File Delete Monitoring
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_UNLINK;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)ctx->args[1]);
    e->sensitive = is_sensitive(e->path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 5. Ptrace (Debugging) Monitoring
SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_PTRACE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->sensitive = 1;   // Ptrace is always high risk

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 6. Network Connect Monitoring
SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->sensitive = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
