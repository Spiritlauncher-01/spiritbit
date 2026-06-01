// SPDX-License-Identifier: GPL-3.0

#include "vmlinux.h"

// Workaround for bpf_stream_vprintk conflict with some libbpf versions
#define bpf_stream_vprintk bpf_stream_vprintk__unused
#include <bpf/bpf_helpers.h>
#undef bpf_stream_vprintk
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ============================================
// CONSTANTS
// ============================================
#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH 16
#endif

#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA 5
#endif

#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA 2
#endif

#define SPIRITBIT_EVENT_VERSION 2
#define EVENT_OPENAT   0x0001
#define EVENT_EXECVE   0x0002
#define EVENT_RENAME   0x0003
#define EVENT_SYMLINK  0x0004
#define EVENT_PTRACE   0x0005
#define EVENT_IOURING  0x0006
#define RATE_WINDOW_NS  1000000000ULL
#define RATE_MAX_EVENTS 1000
#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16

// ============================================
// STRUCT DEFINITIONS
// ============================================
struct event {
    __u8   version;
    __u32  pid;
    __u32  ppid;
    __u32  uid;
    __u64  timestamp;
    __u64  start_time;
    char comm[MAX_COMM_LEN];
    char parent_comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u32  flags;
    __u32  open_flags;
    int    fd;
    __u8   truncated;
    __u8   valid;
};

struct pending_open {
    __u32  pid;
    __u64  timestamp;
    __u32  open_flags;
    __u8   truncated;
    __u8   valid;
    char filename[MAX_FILENAME_LEN];
};

struct rate_entry {
    __u64 count;
    __u64 window_start;
};

struct rate_alert {
    __u32 pid;
    __u64 event_count;
    __u64 timestamp;
};

// ============================================
// MAPS
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rate_alerts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct rate_entry);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct pending_open);
} pending SEC(".maps");

// Scratch maps with proper typing
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_FILENAME_LEN]);
} scratch_filename SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_open);
} scratch_pending SEC(".maps");

// Fixed: Two buffers for rename syscall (Error 4 fix)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, char[MAX_FILENAME_LEN]);
} scratch_rename_paths SEC(".maps");

// ============================================
// HELPER FUNCTIONS
// ============================================

// Fixed: Added length checking to prevent out-of-bounds access
static inline int is_sensitive_path(const char *filename, int len)
{
    if (!filename || len < 4) return 0;
    
    if (len >= 5 && filename[0] == '/' && filename[1] == 'e' && 
        filename[2] == 't' && filename[3] == 'c' && filename[4] == '/') 
        return 1;
    
    if (len >= 4 && filename[0] == '/' && filename[1] == 'e' && 
        filename[2] == 't' && filename[3] == 'c') {
        if (len == 4 || filename[4] == '/' || filename[4] == '\0') 
            return 1;
    }
    
    if (len >= 6 && filename[0] == '/' && filename[1] == 'r' && 
        filename[2] == 'o' && filename[3] == 'o' && filename[4] == 't' && filename[5] == '/') 
        return 1;
    
    if (len >= 5 && filename[0] == '/' && filename[1] == 'r' && 
        filename[2] == 'o' && filename[3] == 'o' && filename[4] == 't') {
        if (len == 5 || filename[5] == '/' || filename[5] == '\0') 
            return 1;
    }
    
    if (len >= 6 && filename[0] == '/' && filename[1] == 'p' && 
        filename[2] == 'r' && filename[3] == 'o' && filename[4] == 'c' && filename[5] == '/') 
        return 1;
    
    if (len >= 6 && filename[0] == '/' && filename[1] == 'h' && 
        filename[2] == 'o' && filename[3] == 'm' && filename[4] == 'e' && filename[5] == '/') 
        return 1;
    
    if (len >= 9 && filename[0] == '/' && filename[1] == 'u' && 
        filename[2] == 's' && filename[3] == 'r' && filename[4] == '/' && 
        filename[5] == 'b' && filename[6] == 'i' && filename[7] == 'n' && filename[8] == '/') 
        return 1;
    
    if (len >= 10 && filename[0] == '/' && filename[1] == 'u' && 
        filename[2] == 's' && filename[3] == 'r' && filename[4] == '/' && 
        filename[5] == 's' && filename[6] == 'b' && filename[7] == 'i' && 
        filename[8] == 'n' && filename[9] == '/') 
        return 1;
    
    if (len >= 9 && filename[0] == '/' && filename[1] == 'u' && 
        filename[2] == 's' && filename[3] == 'r' && filename[4] == '/' && 
        filename[5] == 'l' && filename[6] == 'i' && filename[7] == 'b' && filename[8] == '/') 
        return 1;
    
    return 0;
}

// Fixed: Integer to string conversion for ptrace (Error 3 fix)
static inline void uint32_to_str(__u32 num, char *buf, int buf_len)
{
    if (!buf || buf_len < 2) return;
    
    if (num == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    
    char temp[12];
    int pos = 0;
    
    while (num > 0 && pos < 11) {
        temp[pos++] = '0' + (num % 10);
        num /= 10;
    }
    
    int i;
    for (i = 0; i < pos && i < buf_len - 1; i++) {
        buf[i] = temp[pos - 1 - i];
    }
    buf[i] = '\0';
}

static inline int is_flooding(__u64 key)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_entry *entry = bpf_map_lookup_elem(&rate_limit, &key);

    if (entry) {
        __u64 elapsed = now - entry->window_start;
        if (elapsed > RATE_WINDOW_NS) {
            struct rate_entry new_entry = { .count = 1, .window_start = now };
            bpf_map_update_elem(&rate_limit, &key, &new_entry, BPF_ANY);
            return 0;
        }
        if (entry->count >= RATE_MAX_EVENTS) {
            struct rate_alert *alert = bpf_ringbuf_reserve(&rate_alerts, sizeof(struct rate_alert), 0);
            if (alert) {
                alert->pid = (__u32)(key >> 32);
                alert->event_count = entry->count;
                alert->timestamp = now;
                bpf_ringbuf_submit(alert, 0);
            }
            return 1;
        }
        __sync_fetch_and_add(&entry->count, 1);
        return 0;
    } else {
        struct rate_entry new_entry = { .count = 1, .window_start = now };
        bpf_map_update_elem(&rate_limit, &key, &new_entry, BPF_ANY);
        return 0;
    }
}

// Fixed: Added proper NULL checking for task structure
static inline int populate_event_common(struct event *e)
{
    if (!e) return 0;
    
    e->valid = 0;
    e->version = SPIRITBIT_EVENT_VERSION;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;

    if (bpf_get_current_comm(e->comm, sizeof(e->comm)) < 0) {
        __builtin_memcpy(e->comm, "unknown", 8);
    }
    
    e->timestamp = bpf_ktime_get_ns();

    // Safe task structure access with proper error handling
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent;
        
        // Safe probe of parent task
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0 && parent) {
            bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
            bpf_probe_read_kernel_str(e->parent_comm, sizeof(e->parent_comm), parent->comm);
            bpf_probe_read_kernel(&e->start_time, sizeof(e->start_time), &task->start_time);
        } else {
            e->ppid = 0;
            __builtin_memcpy(e->parent_comm, "init", 5);
            e->start_time = 0;
        }
    } else {
        e->ppid = 0;
        __builtin_memcpy(e->parent_comm, "unknown", 8);
        e->start_time = 0;
    }

    e->valid = 1;
    return 1;
}

// ============================================
// OPENAT HOOKS
// ============================================
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    char *filename = bpf_map_lookup_elem(&scratch_filename, &zero);
    if (!filename) return 0;

    int bytes_read = bpf_probe_read_user_str(filename, MAX_FILENAME_LEN, (void *)ctx->args[1]);
    if (bytes_read <= 1) return 0;
    if (!is_sensitive_path(filename, bytes_read)) return 0;
    if (is_flooding(key)) return 0;

    struct pending_open *p = bpf_map_lookup_elem(&scratch_pending, &zero);
    if (!p) return 0;

    __builtin_memset(p, 0, sizeof(*p));
    p->pid = (__u32)(key >> 32);
    p->timestamp = bpf_ktime_get_ns();
    p->open_flags = (__u32)ctx->args[2];
    p->truncated = (bytes_read == MAX_FILENAME_LEN) ? 1 : 0;
    __builtin_memcpy(p->filename, filename, MAX_FILENAME_LEN);

    bpf_map_update_elem(&pending, &key, p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_open *p = bpf_map_lookup_elem(&pending, &key);
    if (!p) return 0;
    
    if ((long)ctx->ret < 0) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    e->flags = EVENT_OPENAT;
    e->open_flags = p->open_flags;
    e->fd = (int)ctx->ret;
    e->truncated = p->truncated;
    __builtin_memcpy(e->filename, p->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

// ============================================
// OPEN HOOKS (legacy syscall)
// ============================================
SEC("tracepoint/syscalls/sys_enter_open")
int handle_open_entry(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    char *filename = bpf_map_lookup_elem(&scratch_filename, &zero);
    if (!filename) return 0;

    int bytes_read = bpf_probe_read_user_str(filename, MAX_FILENAME_LEN, (void *)ctx->args[0]);
    if (bytes_read <= 1) return 0;
    if (!is_sensitive_path(filename, bytes_read)) return 0;
    if (is_flooding(key)) return 0;

    struct pending_open *p = bpf_map_lookup_elem(&scratch_pending, &zero);
    if (!p) return 0;

    __builtin_memset(p, 0, sizeof(*p));
    p->pid = (__u32)(key >> 32);
    p->timestamp = bpf_ktime_get_ns();
    p->open_flags = (__u32)ctx->args[1];
    p->truncated = (bytes_read == MAX_FILENAME_LEN) ? 1 : 0;
    __builtin_memcpy(p->filename, filename, MAX_FILENAME_LEN);

    bpf_map_update_elem(&pending, &key, p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_open *p = bpf_map_lookup_elem(&pending, &key);
    if (!p) return 0;
    
    if ((long)ctx->ret < 0) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    e->flags = EVENT_OPENAT;
    e->open_flags = p->open_flags;
    e->fd = (int)ctx->ret;
    e->truncated = p->truncated;
    __builtin_memcpy(e->filename, p->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

// ============================================
// EXECVE HOOK
// ============================================
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    if (is_flooding(key)) return 0;

    __u32 zero = 0;
    char *filename = bpf_map_lookup_elem(&scratch_filename, &zero);
    if (!filename) return 0;

    int bytes_read = bpf_probe_read_user_str(filename, MAX_FILENAME_LEN, (void *)ctx->args[0]);
    if (bytes_read <= 0) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_EXECVE;
    e->truncated = (bytes_read == MAX_FILENAME_LEN) ? 1 : 0;
    __builtin_memcpy(e->filename, filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// RENAME HOOK (FIXED - Error 4)
// ============================================
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 idx_old = 0, idx_new = 1;

    char *oldpath = bpf_map_lookup_elem(&scratch_rename_paths, &idx_old);
    if (!oldpath) return 0;

    char *newpath = bpf_map_lookup_elem(&scratch_rename_paths, &idx_new);
    if (!newpath) return 0;

    int old_len = bpf_probe_read_user_str(oldpath, MAX_FILENAME_LEN, (void *)ctx->args[0]);
    int new_len = bpf_probe_read_user_str(newpath, MAX_FILENAME_LEN, (void *)ctx->args[1]);
    
    if (new_len <= 1 && old_len <= 1) return 0;

    if (!is_sensitive_path(newpath, new_len) && !is_sensitive_path(oldpath, old_len)) 
        return 0;
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_RENAME;
    __builtin_memcpy(e->filename, newpath, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// SYMLINK HOOK
// ============================================
SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_symlink(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    char *linkpath = bpf_map_lookup_elem(&scratch_filename, &zero);
    if (!linkpath) return 0;

    int bytes_read = bpf_probe_read_user_str(linkpath, MAX_FILENAME_LEN, (void *)ctx->args[1]);
    if (bytes_read <= 1) return 0;
    if (!is_sensitive_path(linkpath, bytes_read)) return 0;
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_SYMLINK;
    __builtin_memcpy(e->filename, linkpath, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// PTRACE HOOK (FIXED - Error 3)
// ============================================
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = ctx->args[0];
    if (request != PTRACE_ATTACH && request != PTRACE_POKEDATA && request != PTRACE_PEEKDATA) {
        return 0;
    }

    __u64 key = bpf_get_current_pid_tgid();
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_PTRACE;
    __u32 target_pid = (__u32)ctx->args[1];
    uint32_to_str(target_pid, e->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// IO_URING HOOK
// ============================================
SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_io_uring(struct trace_event_raw_sys_enter *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_IOURING;
    const char marker[] = "[io_uring]";
    __builtin_memcpy(e->filename, marker, sizeof(marker));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// PROCESS EXIT HOOK (cleanup)
// ============================================
SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending, &key);
    bpf_map_delete_elem(&rate_limit, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
