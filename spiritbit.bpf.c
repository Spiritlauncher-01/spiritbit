// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#define bpf_stream_vprintk bpf_stream_vprintk__unused
#include <bpf/bpf_helpers.h>
#undef bpf_stream_vprintk
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define SPIRITBIT_EVENT_VERSION 4

#define EVENT_EXECVE   1
#define EVENT_OPENAT   2
#define EVENT_PTRACE   3
#define EVENT_CONNECT  4
#define EVENT_RENAME   5

// Event structure passed from kernel to userspace
struct event {
    __u8  version;           // For compatibility checking
    __u32 pid;               // Process ID
    __u32 ppid;              // Parent Process ID
    __u32 uid;               // User ID
    __u64 ts;                // Timestamp in nanoseconds
    char comm[16];           // Command name
    char path[128];          // File/path involved
    __u32 event_type;        // Type of event
    __u8  sensitive;         // Is this a sensitive path?
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);   // Controlled from config.h
} rb SEC(".maps");

// Helper: Check if path is sensitive (Zero Trust - high scrutiny)
static bool is_sensitive(const char *p) {
    if (bpf_strncmp(p, 5, "/etc/") == 0) return true;
    if (bpf_strncmp(p, 6, "/root/") == 0) return true;
    if (bpf_strncmp(p, 5, "/.ssh") == 0) return true;
    if (bpf_strncmp(p, 8, "/bin/su") == 0) return true;
    return false;
}

// Hook for new process execution (very important for detection)
SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->version = SPIRITBIT_EVENT_VERSION;
    e->event_type = EVENT_EXECVE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (void*)ctx->args[0]);
    e->sensitive = is_sensitive(e->path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// TODO: Add more tracepoints (openat, ptrace, connect, etc.) as needed

char _license[] SEC("license") = "GPL";
