// Spiritbit kernel side eBPF program
// Hooks into kernel syscalls
// Collects events and sends to userspace
// Version 0.2.0

// Core eBPF definitions
// Helper functions, map types, program types

// Kernel process definitions
// task_struct, sched.h gives us process info
#include "vmlinux"

// eBPF helper macros
// SEC macro for section placement
// BPF_MAP_TYPE definitions
#define bpf_stream_vprintk bpf_stream_vprintk__unused
#include <bpf/bpf_helpers.h>
#undef bpf_stream_vprintk

// Tracing helpers
// For reading syscall arguments safely
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH 16
#endif

#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA 5
#endif

#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA 2
#endif

// Version field in event struct
// Kernel and userspace must agree on this
// If they differ userspace rejects event
// Prevents silent data corruption on update
#define SPIRITBIT_EVENT_VERSION 2

// Event type markers
// Stored in flags field
// Tells userspace what kind of event this is
#define EVENT_OPENAT   0x0001  // file open
#define EVENT_EXECVE   0x0002  // process execution
#define EVENT_RENAME   0x0003  // file rename
#define EVENT_SYMLINK  0x0004  // symlink creation
#define EVENT_PTRACE   0x0005  // process tracing
#define EVENT_IOURING  0x0006  // io_uring usage

// Main event struct
// Sent from kernel to userspace via ring buffer
// Must match userspace definition exactly
// version field ensures this
struct event {
    u8   version;           // struct version, must match userspace
    u32  pid;               // process ID
    u32  ppid;              // parent process ID
    u32  uid;               // user ID running process
    u64  timestamp;         // nanoseconds since boot
    u64  start_time;        // process start time for identity verification
    char comm[16];          // process name (kernel limit 16 chars)
    char parent_comm[16];   // parent process name
    char filename[256];     // file being accessed or action target
    u32  flags;             // event type (EVENT_OPENAT etc)
    u32  open_flags;        // openat flags (O_RDONLY, O_WRONLY etc)
    int  fd;                // file descriptor returned by kernel
    u8   truncated;         // 1 if filename exceeded 256 chars
    u8   valid;             // 1 if all fields populated successfully
};

// Pending open entry
// Stores information between entry and exit hooks
// Needed because exit hook ctx has no syscall args
struct pending_open {
    u32  pid;               // process ID
    u64  timestamp;         // when open was requested
    u32  open_flags;        // flags requested (read/write/exec)
    u8   truncated;         // was filename truncated
    char filename[256];     // filename requested at entry
};

// Ring buffer for main events
// Kernel writes events here
// Userspace reads and scores them
// 2MB: larger than before to handle new syscall hooks
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2MB
} events SEC(".maps");

// Ring buffer for rate limit alerts
// Separate from main events
// Tells userspace when a process is being rate limited
// Userspace cannot distinguish rate limited from quiet
// without this separate channel
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64KB, alerts are small
} rate_alerts SEC(".maps");

// Rate limit map
// Tracks event rate per process
// Time windowed to prevent permanent blocking
// Key: pid_tgid (full 64 bits, unique per process lifetime)
// Value: rate_entry with count and window start time

struct rate_entry {
    u64 count;          // events in current window
    u64 window_start;   // nanoseconds when window started
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);               // pid_tgid not just pid
    __type(value, struct rate_entry);
} rate_limit SEC(".maps");

// Pending open map
// Stores entry hook data until exit hook fires
// Key: pid_tgid (unique per process lifetime)
// Prevents PID reuse attacks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);                   // pid_tgid key
    __type(value, struct pending_open);
} pending SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    // Use scratch map instead of stack
    // Avoids 512 byte stack limit
    int zero = 0;
    char *filename = bpf_map_lookup_elem(
        &scratch_filename, &zero
    );
    if (!filename) return 0;

    int bytes_read = bpf_probe_read_user_str(
        filename,
        256,
        (void *)ctx->args[1]
    );

    if (bytes_read <= 0) return 0;
    if (!is_sensitive_path(filename)) return 0;
    if (is_flooding(key)) return 0;

    // Get scratch pending struct
    struct pending_open *p = bpf_map_lookup_elem(
        &scratch_pending, &zero
    );
    if (!p) return 0;

    // Clear it first
    __builtin_memset(p, 0, sizeof(*p));

    p->pid = key >> 32;
    p->timestamp = bpf_ktime_get_ns();
    p->open_flags = (u32)ctx->args[2];
    p->truncated = (bytes_read == 256) ? 1 : 0;
    __builtin_memcpy(p->filename, filename, 256);

    bpf_map_update_elem(&pending, &key, p, BPF_ANY);

    return 0;
}

// Rate alert struct
// Sent when process exceeds rate limit
struct rate_alert {
    u32 pid;
    u64 event_count;
    u64 timestamp;
};

// Window size for rate limiting
// 1 second = 1,000,000,000 nanoseconds
#define RATE_WINDOW_NS  1000000000ULL

// Maximum events per second per process
// 1000 is already suspicious for file monitoring
#define RATE_MAX_EVENTS 1000

// Rate limiter with time window
// Returns 1 if flooding, 0 if normal
// Window resets automatically
// Legitimate processes never permanently blocked
// Fix for original never-resetting counter bug
static inline int is_flooding(u64 key)
{
    u64 now = bpf_ktime_get_ns();

    struct rate_entry *entry = bpf_map_lookup_elem(
        &rate_limit, &key
    );

    if (entry) {
        u64 elapsed = now - entry->window_start;

        if (elapsed > RATE_WINDOW_NS) {
            // Window expired, reset for new window
            // Legitimate processes get fresh start
            // Cannot be permanently blacklisted
            struct rate_entry new_entry = {
                .count = 1,
                .window_start = now
            };
            bpf_map_update_elem(
                &rate_limit, &key, &new_entry, BPF_ANY
            );
            return 0; // fresh window, not flooding
        }

        if (entry->count >= RATE_MAX_EVENTS) {
            // Genuinely flooding within time window
            // Alert userspace via rate_alerts ring buffer
            struct rate_alert *alert = bpf_ringbuf_reserve(
                &rate_alerts,
                sizeof(struct rate_alert),
                0
            );
            if (alert) {
                alert->pid = (u32)(key >> 32);
                alert->event_count = entry->count;
                alert->timestamp = now;
                bpf_ringbuf_submit(alert, 0);
            }
            return 1; // flooding
        }

        // Increment atomically
        // Safe on multi-core systems
        __sync_fetch_and_add(&entry->count, 1);
        return 0;

    } else {
        // First event from this process
        struct rate_entry new_entry = {
            .count = 1,
            .window_start = now
        };
        bpf_map_update_elem(
            &rate_limit, &key, &new_entry, BPF_ANY
        );
        return 0;
    }
}

// Sensitive path check
// Returns 1 if path should be monitored
// Returns 0 if boring, skip to save ring buffer space
// Fix: checks directory boundary (fifth char is / or null)
// Prevents /etcfake matching /etc
static inline int is_sensitive_path(char *filename)
{
    // /etc/ directory and contents
    // Contains passwd, shadow, sudoers, ssh config
    if (__builtin_memcmp(filename, "/etc/", 5) == 0)
        return 1;

    // /etc itself (exact match)
    if (__builtin_memcmp(filename, "/etc", 4) == 0 &&
        (filename[4] == '/' || filename[4] == '\0'))
        return 1;

    // /root/ home directory
    if (__builtin_memcmp(filename, "/root/", 6) == 0)
        return 1;

    // /root itself
    if (__builtin_memcmp(filename, "/root", 5) == 0 &&
        (filename[5] == '/' || filename[5] == '\0'))
        return 1;

    // /proc/ virtual filesystem
    // Used in /proc/self/fd bypass attacks
    if (__builtin_memcmp(filename, "/proc/", 6) == 0)
        return 1;

    // /home/ user directories
    // SSH keys, configs, sensitive user data
    if (__builtin_memcmp(filename, "/home/", 6) == 0)
        return 1;

    // System binary directories
    // Catches binary replacement attacks
    // Attacker replacing /usr/bin/passwd with malicious copy
    if (__builtin_memcmp(filename, "/usr/bin/", 9) == 0)
        return 1;

    if (__builtin_memcmp(filename, "/usr/sbin/", 10) == 0)
        return 1;

    // System library directory
    // Catches library injection attacks
    if (__builtin_memcmp(filename, "/usr/lib/", 9) == 0)
        return 1;

    // Not sensitive, skip this event
    // Reduces ring buffer pressure by ~80%
    return 0;
}

// Helper to populate common event fields
// Used by all hooks to avoid code duplication
// Returns 1 on success, 0 on failure
// If any field fails we mark event invalid
// Prevents partially filled events reaching scorer
// Fix for partial event submission vulnerability
static inline int populate_event_common(struct event *e)
{
    if (!e) return 0;

    // Mark as invalid until fully populated
    // Userspace will reject invalid events
    e->valid = 0;
    e->version = SPIRITBIT_EVENT_VERSION;

    // Get pid and tgid packed together
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32; // upper 32 bits = PID

    // Get uid and gid packed together
    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF; // lower 32 bits = UID

    // Get process name
    // Kernel limits to 16 characters
    int ret = bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (ret < 0) return 0; // failed, mark invalid

    // Get current timestamp
    e->timestamp = bpf_ktime_get_ns();

    // Get parent process information
    // bpf_get_current_task gives kernel task_struct
    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    struct task_struct *parent = NULL;
    ret = bpf_probe_read_kernel(
        &parent,
        sizeof(parent),
        &task->real_parent
    );

    if (ret == 0 && parent) {
        // Parent exists, get its PID
        u32 ppid = 0;
        bpf_probe_read_kernel(
            &ppid, sizeof(ppid), &parent->tgid
        );
        e->ppid = ppid;

        // Get parent process name
        bpf_probe_read_kernel_str(
            e->parent_comm,
            sizeof(e->parent_comm),
            parent->comm
        );

        // Get process start time for identity verification
        // start_time is unique per process instance
        // Even if PID is reused start_time differs
        // Used in safe_freeze to prevent wrong process freeze
        u64 start_time = 0;
        bpf_probe_read_kernel(
            &start_time,
            sizeof(start_time),
            &task->start_time
        );
        e->start_time = start_time;
    }

    // All common fields populated successfully
    e->valid = 1;
    return 1;
}

// openat entry hook
// Fires when any process starts opening a file
// Stores information in pending map
// Exit hook will complete the event
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 pid = key >> 32;

    char filename[256];

    // Read filename from userspace memory
    // bpf_probe_read_user_str is the only safe way
    // Cannot dereference userspace pointer directly in eBPF
    int bytes_read = bpf_probe_read_user_str(
        filename,
        sizeof(filename),
        (void *)ctx->args[1] // openat arg1 = pathname
    );

    // Fix: validate bytes_read before using buffer
    // bytes_read <= 0 means read failed entirely
    // Could be bad pointer, unmapped memory, fault injection
    // Using uninitialized buffer = scoring garbage = wrong results
    if (bytes_read <= 0) return 0;

    // Check if this path is interesting
    // If not skip early to save ring buffer space
    if (!is_sensitive_path(filename)) return 0;

    // Check rate limiting
    if (is_flooding(key)) return 0;

    // Store event data for exit hook
    struct pending_open p = {};
    p.pid = pid;
    p.timestamp = bpf_ktime_get_ns();

    // Fix: save flags at entry time
    // Exit hook ctx is trace_event_raw_sys_exit
    // It only has ret field, no args
    // Reading args at exit = undefined memory
    p.open_flags = (u32)ctx->args[2]; // openat arg2 = flags

    // Check for truncation
    // bytes_read == sizeof means we hit the limit
    // Real path is longer than 256 chars
    // Could be path padding attack
    p.truncated = (bytes_read == sizeof(filename)) ? 1 : 0;

    // Copy filename safely
    __builtin_memcpy(p.filename, filename, sizeof(filename));

    // Store in pending map keyed by pid_tgid
    // Not just pid: prevents PID reuse attacks
    // If process dies and PID reused
    // New process has different pid_tgid
    // Map lookup misses correctly
    bpf_map_update_elem(&pending, &key, &p, BPF_ANY);

    return 0;
}

// openat exit hook
// Fires when openat syscall completes
// Builds full event and sends to userspace
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    // Look up pending entry using full pid_tgid key
    struct pending_open *p = bpf_map_lookup_elem(
        &pending, &key
    );

    // No pending entry means this path wasn't sensitive
    // or rate limited, skip it
    if (!p) return 0;

    // Negative return value means syscall failed
    // File didn't open, nothing to score
    if (ctx->ret < 0) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    // Reserve space in ring buffer
    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );

    // Critical: always check reserve result
    // Ring buffer full returns NULL
    // Dereferencing NULL = kernel panic
    // eBPF verifier requires this check
    if (!e) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    // Populate common fields
    // Returns 0 on failure
    if (!populate_event_common(e)) {
        // Field population failed
        // Discard partially filled event
        // Better to lose event than score garbage
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    // Populate openat specific fields
    e->flags = EVENT_OPENAT;         // event type marker
    e->open_flags = p->open_flags;   // read/write/exec flags from entry
    e->fd = (int)ctx->ret;           // actual fd returned by kernel
    e->truncated = p->truncated;     // was filename truncated

    // Copy filename from pending entry
    // This is what was requested at entry time
    // Userspace will compare to what fd actually points to
    __builtin_memcpy(e->filename, p->filename, sizeof(e->filename));

    // Submit event to ring buffer
    // handle_event in userspace will be called
    bpf_ringbuf_submit(e, 0);

    // Clean up pending entry
    bpf_map_delete_elem(&pending, &key);

    return 0;
}

// open() hook (older syscall, still works)
// Same as openat but different argument positions
// args[0] = pathname (not args[1] like openat)
// args[1] = flags (not args[2])
SEC("tracepoint/syscalls/sys_enter_open")
int handle_open_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    char filename[256];
    int bytes_read = bpf_probe_read_user_str(
        filename,
        sizeof(filename),
        (void *)ctx->args[0] // open arg0 = pathname (different from openat)
    );

    if (bytes_read <= 0) return 0;
    if (!is_sensitive_path(filename)) return 0;
    if (is_flooding(key)) return 0;

    struct pending_open p = {};
    p.pid = key >> 32;
    p.timestamp = bpf_ktime_get_ns();
    p.open_flags = (u32)ctx->args[1]; // open arg1 = flags
    p.truncated = (bytes_read == sizeof(filename)) ? 1 : 0;
    __builtin_memcpy(p.filename, filename, sizeof(filename));

    bpf_map_update_elem(&pending, &key, &p, BPF_ANY);
    return 0;
}

// open() exit hook
// Mirrors openat exit hook
SEC("tracepoint/syscalls/sys_exit_open")
int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    struct pending_open *p = bpf_map_lookup_elem(&pending, &key);
    if (!p) return 0;
    if (ctx->ret < 0) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
    if (!e) {
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }

    e->flags = EVENT_OPENAT; // same event type as openat
    e->open_flags = p->open_flags;
    e->fd = (int)ctx->ret;
    e->truncated = p->truncated;
    __builtin_memcpy(e->filename, p->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

// execve hook
// Fires when any process executes a binary
// Critical: catches malware execution
// Not just file access but actual running of code
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    if (is_flooding(key)) return 0;

    char filename[256];
    int bytes_read = bpf_probe_read_user_str(
        filename,
        sizeof(filename),
        (void *)ctx->args[0] // execve arg0 = pathname
    );

    if (bytes_read <= 0) return 0;

    // Always track execve regardless of path
    // Executing anything is important to monitor
    // Especially binaries in suspicious locations
    // /tmp/backdoor, /dev/shm/payload etc

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_EXECVE;
    e->truncated = (bytes_read == sizeof(filename)) ? 1 : 0;
    __builtin_memcpy(e->filename, filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// rename hook
// Fires when file is renamed
// Attack: rename malicious file to /etc/shadow
// Replaces real shadow file with attacker controlled one
// Or renames sensitive file away to make monitoring miss it
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    // rename(oldpath, newpath)
    // We care about destination (newpath)
    // Is attacker renaming something INTO sensitive location?
    char newpath[256];
    int bytes_read = bpf_probe_read_user_str(
        newpath,
        sizeof(newpath),
        (void *)ctx->args[1] // rename arg1 = newpath
    );

    if (bytes_read <= 0) return 0;

    // Also check oldpath
    // Is attacker renaming sensitive file AWAY?
    // This could be preparation for replacement
    char oldpath[256];
    bpf_probe_read_user_str(
        oldpath,
        sizeof(oldpath),
        (void *)ctx->args[0] // rename arg0 = oldpath
    );

    // Flag if either path is sensitive
    if (!is_sensitive_path(newpath) && !is_sensitive_path(oldpath))
        return 0;

    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_RENAME;
    // Store new path in filename for scoring
    __builtin_memcpy(e->filename, newpath, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// symlink hook
// Fires when symlink is created
// Attack: create symlink in /etc/ pointing to attacker file
// When Spiritbit reads inode it gets attacker file inode
// Or: create /tmp/etc_shadow -> /etc/shadow
// Then use /tmp/etc_shadow path to bypass monitoring
SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_symlink(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();

    // symlink(target, linkpath)
    // linkpath is where symlink is created
    char linkpath[256];
    int bytes_read = bpf_probe_read_user_str(
        linkpath,
        sizeof(linkpath),
        (void *)ctx->args[1] // symlink arg1 = linkpath
    );

    if (bytes_read <= 0) return 0;
    if (!is_sensitive_path(linkpath)) return 0;
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
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

// ptrace hook
// Fires when process tries to trace another process
// Used for: debuggers (legitimate), process injection (malicious)
// Catch: unknown process attaching to known sensitive process
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = ctx->args[0];

    // Only flag suspicious ptrace requests
    // PTRACE_ATTACH: attaching to process (injection setup)
    // PTRACE_POKEDATA: writing to process memory (injection)
    // PTRACE_PEEKDATA: reading process memory (information leak)
    // Skip PTRACE_CONT, PTRACE_DETACH etc (normal debugging)
    if (request != PTRACE_ATTACH &&
        request != PTRACE_POKEDATA &&
        request != PTRACE_PEEKDATA) {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_PTRACE;

    // Store target PID and request type in filename field
    // Repurposed field: no real filename for ptrace
    u32 target_pid = (u32)ctx->args[1];
    // Use __builtin_snprintf if available
    // Otherwise just store target pid in first bytes
    e->filename[0] = (target_pid >> 24) & 0xFF;
    e->filename[1] = (target_pid >> 16) & 0xFF;
    e->filename[2] = (target_pid >> 8)  & 0xFF;
    e->filename[3] = (target_pid)       & 0xFF;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// io_uring hook
// io_uring bypasses traditional syscall hooks
// Cannot inspect individual operations
// But can flag processes using io_uring
// Unknown processes using io_uring = elevated suspicion
SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_io_uring(struct trace_event_raw_sys_enter *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    if (is_flooding(key)) return 0;

    struct event *e = bpf_ringbuf_reserve(
        &events, sizeof(struct event), 0
    );
    if (!e) return 0;

    if (!populate_event_common(e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->flags = EVENT_IOURING;

    // Marker in filename field
    // Userspace will see [io_uring] and handle specially
    const char marker[] = "[io_uring]";
    __builtin_memcpy(e->filename, marker, sizeof(marker));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Process exit hook
// Fires when any process exits
// Cleans up pending map entries immediately
// Prevents map leak from process dying between entry/exit hooks
// Without this: attacker can fill pending map by fork/crash loop
SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(
    struct trace_event_raw_sched_process_template *ctx
)
{
    u64 key = bpf_get_current_pid_tgid();

    // Delete pending entry if exists
    // Safe to call even if no entry: returns error we ignore
    bpf_map_delete_elem(&pending, &key);

    // Delete rate limit entry
    // Dead process should not occupy rate limit table
    bpf_map_delete_elem(&rate_limit, &key);

    return 0;
}

// Required license declaration
// GPL required for access to certain kernel helper functions
// Without this some helpers are unavailable
// eBPF verifier enforces this
char LICENSE[] SEC("license") = "GPL";
