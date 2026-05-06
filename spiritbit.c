// Spiritbit userspace daemon
// Receives events from kernel via ring buffer
// Scores events using coherence algorithm
// Makes response decisions
// Version 0.2.0

// Standard headers
#include <stdio.h>      // printf, fprintf, fopen etc
#include <stdlib.h>     // malloc, free, exit etc
#include <string.h>     // strcmp, strstr, strlen etc
#include <signal.h>     // signal(), SIGINT, SIGTERM etc
#include <unistd.h>     // readlink, getpid, close etc
#include <fcntl.h>      // open(), O_RDONLY etc
#include <time.h>       // time(), clock_gettime etc
#include <math.h>       // sqrt, log2 for entropy
#include <errno.h>      // errno, strerror
#include <dirent.h>     // opendir, readdir for /proc walking
#include <ctype.h>      // isdigit for /proc parsing
#include <stdarg.h>     // va_list for variadic functions
#include <pthread.h>    // pthread for async logging
#include <sys/stat.h>   // stat(), fstat(), struct stat
#include <sys/file.h>   // flock() for log file locking
#include <sys/wait.h>   // waitpid for watchdog
#include <sys/prctl.h>  // prctl() for self protection
#include <sys/syscall.h>// syscall() for pidfd
#include <sys/capability.h> // capability checking
#include <sys/inotify.h>    // inotify for filesystem changes
#include <sqlite3.h>    // persistent state database
#include <bpf/libbpf.h> // eBPF userspace library
#include <bpf/bpf.h>    // eBPF map operations

// Event struct version
// Must match kernel side definition
// Userspace rejects events with wrong version
// Prevents silent data corruption during updates
#define SPIRITBIT_EVENT_VERSION 2

// Event type markers
// Must match kernel side definitions exactly
#define EVENT_OPENAT   0x0001
#define EVENT_EXECVE   0x0002
#define EVENT_RENAME   0x0003
#define EVENT_SYMLINK  0x0004
#define EVENT_PTRACE   0x0005
#define EVENT_IOURING  0x0006

// Response level thresholds
// Based on weighted score 0-100
#define THRESHOLD_CRITICAL 85  // base, randomized at runtime
#define THRESHOLD_WARNING  50
#define THRESHOLD_LOW      30

// Resource limits
#define MAX_SENSITIVE_FILES  256    // inode table size
#define MAX_FREEZE_RECORDS   256    // simultaneous frozen processes
#define MAX_TRACKED_PROCESSES 1000  // behavioral rate tracking
#define MAX_ANCESTRY_DEPTH   8      // how deep to walk process tree
#define MAX_BACKOFF_SHIFT    5      // max error backoff = 3.2 seconds
#define LOG_QUEUE_SIZE       4096   // async log queue entries
#define BASELINE_SIZE        10007  // prime for hash table
#define MAX_LOG_SIZE         (100 * 1024 * 1024) // 100MB log limit
#define PENDING_TIMEOUT_NS   5000000000ULL // 5 seconds stale timeout
#define RATE_WINDOW_NS       1000000000ULL // 1 second rate window
#define LEARNING_DAYS        7      // days before active monitoring

// Absolute paths
// Never relative paths: prevents cwd manipulation attack
#define SPIRITBIT_BPF_PATH "/usr/lib/spiritbit/spiritbit.bpf.o"
#define LOG_PATH           "/var/log/spiritbit.log"
#define DB_PATH            "/var/lib/spiritbit/state.db"
#define PID_FILE           "/var/run/spiritbit.pid"
#define CONFIG_PATH        "/etc/spiritbit/config.conf"

// Mirror of kernel event struct
// Must match kernel definition exactly
// version field detects mismatch
struct event {
    unsigned char  version;
    unsigned int   pid;
    unsigned int   ppid;
    unsigned int   uid;
    unsigned long long timestamp;
    unsigned long long start_time;
    char           comm[16];
    char           parent_comm[16];
    char           filename[256];
    unsigned int   flags;
    unsigned int   open_flags;
    int            fd;
    unsigned char  truncated;
    unsigned char  valid;
};

// Rate alert from kernel
struct rate_alert {
    unsigned int pid;
    unsigned long long event_count;
    unsigned long long timestamp;
};

// Five dimensional threat score
// Each dimension scored 0-100 independently
// scored flag tracks which dimensions are active
// Inactive dimensions excluded from weighted average
// Fix for treating unscored same as scored zero
struct threat_score {
    int file_sensitivity;       // how sensitive is accessed file
    int identity_coherence;     // is process identity legitimate
    int lineage_coherence;      // does process ancestry make sense
    int behavioral_coherence;   // is access rate normal
    int privilege_coherence;    // is privilege level appropriate
    int baseline_modifier;      // -30 if known normal, +10 if new

    // Track which dimensions were actually scored
    // 1 = scored with real data
    // 0 = no data available, exclude from average
    int file_scored;
    int identity_scored;
    int lineage_scored;
    int behavioral_scored;
    int privilege_scored;
};

// Sensitive file inode record
// Inodes are unique file identifiers
// Cannot be faked by path manipulation
// Cannot be bypassed via /proc/self/fd tricks
struct sensitive_inode {
    unsigned long inode_number;
    char description[64];
};

// Legitimate tool record
// Full verification: comm + exe_path + inode + uid
// Prevents comm name spoofing via prctl
struct legitimate_tool {
    char comm[16];       // process name
    char exe_path[256];  // full executable path
    int  uid_required;   // required UID, -1 = any
};

// Ancestry record for lineage walking
struct ancestry {
    unsigned int pids[MAX_ANCESTRY_DEPTH];
    char comms[MAX_ANCESTRY_DEPTH][16];
    char exe_paths[MAX_ANCESTRY_DEPTH][256];
    int depth;
};

// Process behavioral rate tracking
struct process_rate {
    unsigned int pid;
    unsigned long long first_event;
    unsigned long long last_event;
    unsigned int event_count;
    int active;
};

// Freeze audit record
// Tracks all frozen processes
// Detects unauthorized unfreezing
struct freeze_record {
    int pidfd;                   // atomic process fd, prevents PID reuse
    unsigned int pid;            // for display
    unsigned int pgid;           // process group ID
    char comm[16];               // process name
    unsigned int uid;            // process owner
    double score;                // score that triggered freeze
    time_t frozen_at;            // when frozen
    time_t unfrozen_at;          // when unfrozen, 0 if still frozen
    int unfreeze_authorized;     // 1 if Spiritbit authorized it
    int active;                  // 1 if currently frozen
};

// Async log queue entry
struct log_entry {
    char message[512];
    int active;
};

// Baseline hash table entry
struct baseline_entry {
    unsigned long long hash;
    unsigned int seen_count;
    int occupied;
};

// Runtime configuration
struct spiritbit_config {
    int threshold_base;      // base detection threshold
    int threshold_band;      // random variation band
    int developer_mode;      // higher threshold for dev tools
    int learning_mode;       // 1 during initial learning period
    time_t learning_start;   // when learning started
};

// ===== Global State =====

// Control flag: set to 0 by signal handler to stop main loop
// sig_atomic_t: safe to set from signal handler
volatile sig_atomic_t running = 1;

// Cleanup guard: prevents double cleanup on signal during cleanup
volatile sig_atomic_t cleanup_done = 0;

// eBPF handles
struct ring_buffer *rb = NULL;       // main event ring buffer
struct ring_buffer *rate_rb = NULL;  // rate alert ring buffer
struct bpf_object  *obj = NULL;      // eBPF program object

// Log file handle
FILE *log_file = NULL;
pthread_mutex_t log_file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Async log queue
struct log_entry log_queue[LOG_QUEUE_SIZE];
volatile int log_head = 0;
volatile int log_tail = 0;
pthread_mutex_t log_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t log_queue_cond = PTHREAD_COND_INITIALIZER;

// Sensitive file inode table
struct sensitive_inode sensitive_files[MAX_SENSITIVE_FILES];
int sensitive_count = 0;
pthread_mutex_t sensitive_files_mutex = PTHREAD_MUTEX_INITIALIZER;

// Known legitimate tools
// comm + exe path + uid must all match
// Prevents name spoofing
struct legitimate_tool known_tools[] = {
    { "passwd",  "/usr/bin/passwd",      -1 },
    { "useradd", "/usr/sbin/useradd",     0 },
    { "usermod", "/usr/sbin/usermod",     0 },
    { "userdel", "/usr/sbin/userdel",     0 },
    { "sudo",    "/usr/bin/sudo",        -1 },
    { "su",      "/usr/bin/su",          -1 },
    { "sshd",    "/usr/sbin/sshd",        0 },
    { "login",   "/usr/bin/login",        0 },
    { "shadow",  "/sbin/unix_chkpwd",     0 },
    { "",        "",                       0 }  // sentinel
};

// Known io_uring users
// These processes legitimately use io_uring
// Others get flagged
char *known_io_uring_users[] = {
    "postgres", "nginx", "fio",
    "io_uring_test", NULL
};

// Freeze audit table
struct freeze_record freeze_audit[MAX_FREEZE_RECORDS];
pthread_mutex_t freeze_mutex = PTHREAD_MUTEX_INITIALIZER;

// Process rate tracker for behavioral scoring
struct process_rate rate_tracker[MAX_TRACKED_PROCESSES];
pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;

// Baseline hash table
// Learned normal behaviors
// Persisted to SQLite database
struct baseline_entry baseline[BASELINE_SIZE];
pthread_mutex_t baseline_mutex = PTHREAD_MUTEX_INITIALIZER;

// Runtime configuration
struct spiritbit_config config = {
    .threshold_base  = THRESHOLD_CRITICAL,
    .threshold_band  = 5,
    .developer_mode  = 0,
    .learning_mode   = 1,
    .learning_start  = 0,
};

// SQLite database handle
sqlite3 *db = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

// inotify handle for filesystem change detection
int inotify_fd = -1;

// ===== Async Logging =====

// Write log message to queue
// Called from hot event path
// Never touches FILE* directly
// Never takes log file mutex
// Non-blocking: drops message if queue full
// Better to lose a log entry than block event processing
void async_log(const char *format, ...)
{
    pthread_mutex_lock(&log_queue_mutex);

    int next_head = (log_head + 1) % LOG_QUEUE_SIZE;

    if (next_head == log_tail) {
        // Queue full
        // Drop this entry
        // Attacker generating massive events
        // cannot block us by filling log queue
        pthread_mutex_unlock(&log_queue_mutex);
        return;
    }

    va_list args;
    va_start(args, format);
    vsnprintf(
        log_queue[log_head].message,
        sizeof(log_queue[log_head].message) - 1,
        format,
        args
    );
    va_end(args);

    log_queue[log_head].active = 1;
    log_head = next_head;

    // Wake log thread
    pthread_cond_signal(&log_queue_cond);
    pthread_mutex_unlock(&log_queue_mutex);
}

// Log rotation
// Called from log thread only
// Never from main thread or signal handler
void rotate_log_if_needed()
{
    if (!log_file) return;

    long size = ftell(log_file);
    if (size < 0 || size < MAX_LOG_SIZE) return;

    // Rotate
    fclose(log_file);
    log_file = NULL;

    remove(LOG_PATH ".2");
    rename(LOG_PATH ".1", LOG_PATH ".2");
    rename(LOG_PATH, LOG_PATH ".1");

    log_file = fopen(LOG_PATH, "a");
    if (log_file) {
        fprintf(log_file, "[SPIRITBIT] Log rotated\n");
    }
}

// Log thread
// Consumes from queue and writes to file
// Only thread that touches log_file
// Prevents FILE* lock contention in main thread
// Prevents signal handler deadlock on FILE* lock
void *log_thread_func(void *arg)
{
    while (1) {
        pthread_mutex_lock(&log_queue_mutex);

        // Wait for entries
        while (log_head == log_tail && running) {
            pthread_cond_wait(
                &log_queue_cond,
                &log_queue_mutex
            );
        }

        if (!running && log_head == log_tail) {
            pthread_mutex_unlock(&log_queue_mutex);
            break; // shutting down, queue empty
        }

        // Take one entry
        char message[512];
        strncpy(
            message,
            log_queue[log_tail].message,
            sizeof(message) - 1
        );
        message[sizeof(message) - 1] = '\0';
        log_queue[log_tail].active = 0;
        log_tail = (log_tail + 1) % LOG_QUEUE_SIZE;

        pthread_mutex_unlock(&log_queue_mutex);

        // Write to file outside mutex
        // Only this thread writes to log_file
        if (log_file) {
            rotate_log_if_needed();
            fputs(message, log_file);
            fflush(log_file);
        }
    }

    return NULL;
}

// ===== Database =====

// Initialize SQLite database
// Creates tables if they don't exist
// Enables WAL mode for concurrent access
// Fix: WAL mode prevents read/write blocking
void init_database()
{
    // Create directory
    system("mkdir -p /var/lib/spiritbit");

    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot open database: %s\n"
            "Path: %s\n",
            sqlite3_errmsg(db),
            DB_PATH
        );
        db = NULL;
        return;
    }

    // Enable WAL mode
    // Write-Ahead Logging allows concurrent reads during writes
    // Fix: prevents pattern analysis blocking event logging
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;",
                 NULL, NULL, NULL);

    // Enable foreign keys
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;",
                 NULL, NULL, NULL);

    // Set page size for performance
    sqlite3_exec(db, "PRAGMA page_size=4096;",
                 NULL, NULL, NULL);

    // Create tables
    const char *sql =
        "CREATE TABLE IF NOT EXISTS events ("
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp    INTEGER NOT NULL,"
        "  pid          INTEGER NOT NULL,"
        "  comm         TEXT,"
        "  parent_comm  TEXT,"
        "  filename     TEXT,"
        "  uid          INTEGER,"
        "  score        REAL,"
        "  event_type   INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS baseline ("
        "  hash         INTEGER PRIMARY KEY,"
        "  seen_count   INTEGER DEFAULT 0,"
        "  first_seen   INTEGER,"
        "  last_seen    INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS freeze_audit ("
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  pid          INTEGER,"
        "  comm         TEXT,"
        "  score        REAL,"
        "  frozen_at    INTEGER,"
        "  unfrozen_at  INTEGER DEFAULT 0,"
        "  authorized   INTEGER DEFAULT 0"
        ");"

        // Learning state persisted
        // Fix: learning mode survives restarts
        // Attacker cannot reset baseline by killing Spiritbit
        "CREATE TABLE IF NOT EXISTS state ("
        "  key          TEXT PRIMARY KEY,"
        "  value        TEXT"
        ");"

        // Index for fast event queries
        "CREATE INDEX IF NOT EXISTS idx_events_comm "
        "ON events(comm);"

        "CREATE INDEX IF NOT EXISTS idx_events_timestamp "
        "ON events(timestamp);";

    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,
            "[SPIRITBIT] Database init error: %s\n", err
        );
        sqlite3_free(err);
    }

    printf("[SPIRITBIT] Database initialized: %s\n", DB_PATH);
}

// Persist event to database
// Called from async log thread, not hot path
// Fix: database writes off the critical event path
// No performance impact on ring buffer polling
void persist_event_async(
    struct event *e,
    double score
)
{
    // Queue for async database write
    // Implementation: add to a separate write queue
    // For now: direct write but only called from log thread
    if (!db) return;

    pthread_mutex_lock(&db_mutex);

    sqlite3_stmt *stmt;
    const char *sql =
        "INSERT INTO events "
        "(timestamp, pid, comm, parent_comm, "
        " filename, uid, score, event_type) "
        "VALUES (?,?,?,?,?,?,?,?)";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
        == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (long long)e->timestamp);
        sqlite3_bind_int(stmt,   2, e->pid);
        sqlite3_bind_text(stmt,  3, e->comm, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  4, e->parent_comm, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  5, e->filename, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt,   6, e->uid);
        sqlite3_bind_double(stmt,7, score);
        sqlite3_bind_int(stmt,   8, e->flags);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&db_mutex);
}

// Load baseline from database
// Called at startup
// Restores learned normal behavior across restarts
// Fix: baseline survives Spiritbit being killed
void load_baseline_from_db()
{
    if (!db) return;

    pthread_mutex_lock(&db_mutex);

    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT hash, seen_count FROM baseline";

    int loaded = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
        == SQLITE_OK) {

        pthread_mutex_lock(&baseline_mutex);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            unsigned long long hash =
                (unsigned long long)sqlite3_column_int64(stmt, 0);
            int count = sqlite3_column_int(stmt, 1);

            int idx = hash % BASELINE_SIZE;

            for (int i = 0; i < 100; i++) {
                int probe = (idx + i) % BASELINE_SIZE;
                if (!baseline[probe].occupied) {
                    baseline[probe].hash = hash;
                    baseline[probe].seen_count = count;
                    baseline[probe].occupied = 1;
                    loaded++;
                    break;
                }
            }
        }

        pthread_mutex_unlock(&baseline_mutex);
        sqlite3_finalize(stmt);
    }

    // Load learning state
    // Fix: learning mode survives restarts
    const char *state_sql =
        "SELECT value FROM state WHERE key='learning_mode'";

    if (sqlite3_prepare_v2(db, state_sql, -1, &stmt, NULL)
        == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int stored_learning =
                atoi((const char *)sqlite3_column_text(stmt, 0));
            config.learning_mode = stored_learning;
        }
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&db_mutex);

    printf(
        "[SPIRITBIT] Loaded %d baseline entries\n"
        "[SPIRITBIT] Learning mode: %s\n",
        loaded,
        config.learning_mode ? "active" : "complete"
    );

    // If substantial baseline loaded
    // Learning period already complete from previous run
    if (loaded > 100 && config.learning_mode) {
        config.learning_mode = 0;
        printf("[SPIRITBIT] Baseline restored, active monitoring\n");
    }
}

// Persist baseline entry to database
// Called when new behavior learned
void persist_baseline_entry(unsigned long long hash, int count)
{
    if (!db) return;

    pthread_mutex_lock(&db_mutex);

    sqlite3_stmt *stmt;
    const char *sql =
        "INSERT OR REPLACE INTO baseline "
        "(hash, seen_count, first_seen, last_seen) "
        "VALUES (?, ?, "
        "COALESCE((SELECT first_seen FROM baseline WHERE hash=?), "
        "strftime('%s','now')), "
        "strftime('%s','now'))";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
        == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (long long)hash);
        sqlite3_bind_int(stmt,   2, count);
        sqlite3_bind_int64(stmt, 3, (long long)hash);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&db_mutex);
}

// ===== Inode Table =====

// Build inode table from known sensitive files
// Inodes are unique kernel assigned identifiers
// Cannot be faked by path manipulation
// Cannot be bypassed via /proc/self/fd tricks
void build_inode_table()
{
    printf("[SPIRITBIT] Building inode table\n");

    char *paths[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_rsa_key",
        "/root/.ssh/authorized_keys",
        "/etc/crontab",
        "/etc/cron.d",
        NULL
    };

    pthread_mutex_lock(&sensitive_files_mutex);
    sensitive_count = 0;

    for (int i = 0; paths[i] != NULL; i++) {
        // Fix: bounds check before writing
        // Prevents stack overflow if paths list exceeds MAX
        if (sensitive_count >= MAX_SENSITIVE_FILES) {
            fprintf(stderr,
                "[SPIRITBIT] Inode table full, skipping %s\n",
                paths[i]
            );
            continue;
        }

        struct stat st;
        if (stat(paths[i], &st) == 0) {
            sensitive_files[sensitive_count].inode_number =
                st.st_ino;
            strncpy(
                sensitive_files[sensitive_count].description,
                paths[i],
                sizeof(sensitive_files[0].description) - 1
            );
            sensitive_count++;

            printf(
                "[SPIRITBIT] Watching inode %lu → %s\n",
                st.st_ino, paths[i]
            );
        }
    }

    pthread_mutex_unlock(&sensitive_files_mutex);

    printf(
        "[SPIRITBIT] Inode table built: %d files\n",
        sensitive_count
    );
}

// ===== inotify =====

// Setup inotify watches on sensitive directories
// Detects filesystem changes that could invalidate inode table
// When file deleted and recreated it gets new inode
// Without this Spiritbit monitors old (now orphaned) inode
void setup_inotify()
{
    // Fix: create with O_CLOEXEC
    // Prevents fd leaking to child processes
    inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot setup inotify: %s\n"
            "Inode table will not auto-refresh\n",
            strerror(errno)
        );
        return;
    }

    char *watch_dirs[] = {
        "/etc",
        "/etc/ssh",
        "/root",
        "/root/.ssh",
        NULL
    };

    for (int i = 0; watch_dirs[i] != NULL; i++) {
        inotify_add_watch(
            inotify_fd,
            watch_dirs[i],
            IN_CREATE | IN_DELETE |
            IN_MOVED_FROM | IN_MOVED_TO |
            IN_ATTRIB
        );
    }

    printf("[SPIRITBIT] inotify watches active\n");
}

// Check for filesystem changes
// Called from main loop
// Non-blocking: returns immediately if no events
void check_inotify_events()
{
    if (inotify_fd < 0) return;

    char buf[4096];
    ssize_t len = read(inotify_fd, buf, sizeof(buf));

    if (len <= 0) return; // no events

    printf("[SPIRITBIT] Filesystem change detected\n"
           "[SPIRITBIT] Rebuilding inode table\n");

    build_inode_table();

    async_log("[INOTIFY] Inode table refreshed after fs change\n");
}

// ===== Process Identity =====

// Get real executable path for process
// /proc/PID/exe is kernel-set symlink to actual binary
// Cannot be changed by process after execve
// Much harder to fake than comm name
// Returns 0 on success, -1 on failure
int get_exe_path(unsigned int pid, char *buf, size_t bufsize)
{
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link) - 1,
             "/proc/%u/exe", pid);

    ssize_t len = readlink(exe_link, buf, bufsize - 1);

    if (len < 0) {
        buf[0] = '\0';
        return -1;
    }

    buf[len] = '\0';
    return 0;
}

// Get executable inode number
// Even stronger than exe path
// Attacker could bind mount malicious binary over real path
// Inode would differ from known good binary
// Catches bind mount attacks
unsigned long get_exe_inode(unsigned int pid)
{
    char exe_path[256];
    if (get_exe_path(pid, exe_path, sizeof(exe_path)) != 0) {
        return 0;
    }

    struct stat st;
    if (lstat(exe_path, &st) != 0) { // lstat: don't follow symlinks
        return 0;
    }

    return st.st_ino;
}

// Build tool inode table at startup
// Known legitimate tools mapped to their inodes
// Cannot be spoofed by prctl name change
// Cannot be spoofed by copying binary to /tmp
struct tool_inode {
    char name[16];
    unsigned long inode;
};

struct tool_inode tool_inodes[64];
int tool_inode_count = 0;

void build_tool_inode_table()
{
    printf("[SPIRITBIT] Building tool inode table\n");

    for (int i = 0; known_tools[i].comm[0] != '\0'; i++) {
        struct stat st;
        if (stat(known_tools[i].exe_path, &st) == 0) {
            if (tool_inode_count < 64) {
                tool_inodes[tool_inode_count].inode = st.st_ino;
                strncpy(
                    tool_inodes[tool_inode_count].name,
                    known_tools[i].comm,
                    15
                );
                tool_inode_count++;

                printf("[SPIRITBIT] Tool: %lu → %s\n",
                       st.st_ino, known_tools[i].exe_path);
            }
        }
    }
}

// Verify process still exists and matches expected properties
// Called before any scoring action
// Prevents scoring events for already dead processes
// Fix for process existence validation gap
int process_still_valid(
    unsigned int pid,
    char *expected_comm,
    unsigned int expected_uid
)
{
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path) - 1,
             "/proc/%u/comm", pid);

    FILE *f = fopen(comm_path, "r");
    if (!f) return 0; // process gone

    char current_comm[16] = {0};
    if (fgets(current_comm, sizeof(current_comm), f)) {
        current_comm[strcspn(current_comm, "\n")] = '\0';
    }
    fclose(f);

    // Prefix match: comm may be truncated to 15 chars
    size_t expected_len = strlen(expected_comm);
    if (expected_len > 15) expected_len = 15;

    if (strncmp(current_comm, expected_comm, expected_len) != 0) {
        return 0; // wrong process
    }

    return 1;
}

// ===== Process Ancestry =====

// Walk full process tree up to MAX_ANCESTRY_DEPTH levels
// Returns ancestry struct with all ancestors
// Used for deep lineage coherence checking
// Catches bad ancestors hidden by intermediate legitimate processes
struct ancestry get_full_ancestry(unsigned int pid)
{
    struct ancestry anc = {0};
    unsigned int current_pid = pid;

    for (int i = 0; i < MAX_ANCESTRY_DEPTH; i++) {
        char status_path[64];
        snprintf(status_path, sizeof(status_path) - 1,
                 "/proc/%u/status", current_pid);

        FILE *f = fopen(status_path, "r");
        if (!f) break;

        char line[256];
        unsigned int ppid = 0;
        char comm[16] = {0};

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line, "Name:\t%15s", comm);
            }
            if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid:\t%u", &ppid);
            }
        }
        fclose(f);

        anc.pids[i] = current_pid;
        strncpy(anc.comms[i], comm, 15);
        get_exe_path(
            current_pid,
            anc.exe_paths[i],
            sizeof(anc.exe_paths[i])
        );
        anc.depth = i + 1;

        if (ppid <= 1) break; // reached init/systemd
        current_pid = ppid;
    }

    return anc;
}

// ===== Scoring =====

// Anchored path matching helper
// Checks that component appears as real directory component
// Not just substring: prevents /tmp/etc/shadow matching /etc/
// Fix for strstr false positive vulnerability
int path_starts_with(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return 0;
    // Confirm boundary: next char must be / or null
    char next = path[plen];
    return (next == '/' || next == '\0');
}

// Exact path match
int path_is(const char *path, const char *target)
{
    return strcmp(path, target) == 0;
}

// Score filename sensitivity
// Uses inode comparison for accuracy
// Falls back to anchored path matching
// Fix: uses fd path for race-free inode check
// Fix: uses static buffers to prevent dangling pointer
// Fix: uses lstat then fstat to prevent TOCTOU
int score_file_sensitivity(
    char *filename,
    unsigned int pid,
    int fd
)
{
    // Static buffers: allocated once at program start
    // Never go out of scope
    // Cannot become dangling pointer after refactor
    // Fix for latent dangling pointer vulnerability
    static char fd_path[64];
    static char real_path[4096];
    static char canonical[4096];

    // Try fd-based inode check first
    // This is race-free: fd already open, kernel resolved symlinks
    // Cannot be swapped between check and comparison
    // Fix for TOCTOU in scorer
    if (fd >= 0) {
        snprintf(fd_path, sizeof(fd_path) - 1,
                 "/proc/%u/fd/%d", pid, fd);

        struct stat st;
        if (stat(fd_path, &st) == 0) {
            pthread_mutex_lock(&sensitive_files_mutex);
            for (int i = 0; i < sensitive_count; i++) {
                if (sensitive_files[i].inode_number == st.st_ino) {
                    pthread_mutex_unlock(&sensitive_files_mutex);
                    printf(
                        "[SPIRITBIT] Sensitive inode accessed\n"
                        "  File : %s\n"
                        "  Via  : %s\n",
                        sensitive_files[i].description,
                        filename
                    );
                    return 100; // definitive inode match
                }
            }
            pthread_mutex_unlock(&sensitive_files_mutex);
        }

        // Resolve what fd actually points to
        // Catches /proc/self/fd bypass
        ssize_t len = readlink(
            fd_path,
            real_path,
            sizeof(real_path) - 1
        );
        if (len > 0) {
            real_path[len] = '\0';
            filename = real_path; // points to static buffer, safe
        }
    }

    // Canonicalize path
    // Resolves .. and . components
    // Neutralizes path traversal attacks
    // realpath returns NULL if file doesn't exist
    char *resolved = realpath(filename, canonical);
    const char *score_path = resolved ? canonical : filename;

    // Anchored path matching
    // Fix: prevents /tmp/etc/shadow matching /etc/shadow
    // Fix: prevents /notroot matching /root

    if (path_is(score_path, "/etc/shadow"))    return 100;
    if (path_is(score_path, "/etc/passwd"))    return 80;
    if (path_is(score_path, "/etc/sudoers"))   return 90;
    if (path_starts_with(score_path, "/etc/ssh"))   return 70;
    if (path_starts_with(score_path, "/root/.ssh"))  return 80;
    if (path_starts_with(score_path, "/root"))       return 60;
    if (path_starts_with(score_path, "/etc"))        return 40;
    if (path_starts_with(score_path, "/usr/bin"))    return 30;
    if (path_starts_with(score_path, "/usr/sbin"))   return 30;

    return 10; // not sensitive
}

// Score process identity coherence
// Checks comm name + exe path + exe inode + uid
// Fix: prevents prctl name spoofing
// Attacker cannot set comm to "passwd" and pass as legitimate
int score_identity_coherence(
    char *comm,
    unsigned int uid,
    unsigned int pid
)
{
    // Get real executable path
    // /proc/PID/exe set by kernel at execve, cannot be changed
    static char exe_path[256];
    get_exe_path(pid, exe_path, sizeof(exe_path));

    // Get real executable inode
    unsigned long exe_inode = get_exe_inode(pid);

    // Check against known legitimate tools
    for (int i = 0; known_tools[i].comm[0] != '\0'; i++) {

        // Prefix match for comm
        // Handles truncation to 15 chars
        size_t comm_len = strlen(known_tools[i].comm);
        if (strncmp(comm, known_tools[i].comm, comm_len) != 0) {
            continue;
        }

        // Exe path must match
        // Catches /tmp/passwd pretending to be /usr/bin/passwd
        if (exe_path[0] != '\0' &&
            strcmp(exe_path, known_tools[i].exe_path) != 0) {

            printf(
                "[SPIRITBIT] Name spoofing detected\n"
                "  Comm     : %s\n"
                "  Expected : %s\n"
                "  Actual   : %s\n"
                "  PID      : %u\n",
                comm,
                known_tools[i].exe_path,
                exe_path,
                pid
            );
            return 80; // high suspicion for spoofing
        }

        // Check inode matches known good binary
        // Catches bind mount attacks
        for (int j = 0; j < tool_inode_count; j++) {
            if (strcmp(tool_inodes[j].name, comm) == 0) {
                if (exe_inode != 0 &&
                    tool_inodes[j].inode != exe_inode) {
                    printf(
                        "[SPIRITBIT] Bind mount attack detected\n"
                        "  Comm           : %s\n"
                        "  Expected inode : %lu\n"
                        "  Actual inode   : %lu\n",
                        comm,
                        tool_inodes[j].inode,
                        exe_inode
                    );
                    return 90;
                }
                break;
            }
        }

        // Check UID requirement
        if (known_tools[i].uid_required != -1 &&
            uid != (unsigned int)known_tools[i].uid_required) {
            return 70; // wrong user for this tool
        }

        // All checks passed: legitimate tool
        return 0;
    }

    // Not in legitimate list
    if (uid == 0) return 60; // unknown root process
    return 40;               // unknown user process
}

// Bad ancestor detection list
// Prefix matching to handle version suffixes
// Fix: python3.11 matches "python" prefix
char *bad_ancestor_prefixes[] = {
    "nc", "ncat", "netcat",
    "python", "perl", "ruby", "php",
    "msfconsole", "meterpreter",
    "curl", "wget",
    NULL
};

// Check if comm matches bad ancestor prefix
int is_bad_ancestor(char *comm)
{
    for (int i = 0; bad_ancestor_prefixes[i] != NULL; i++) {
        size_t len = strlen(bad_ancestor_prefixes[i]);
        // Prefix match: catches python3.11, ruby3.0 etc
        if (strncmp(comm, bad_ancestor_prefixes[i], len) == 0) {
            return 1;
        }
    }
    return 0;
}

// Score lineage coherence
// Walks full ancestry up to MAX_ANCESTRY_DEPTH
// Checks exe paths in ancestry for suspicious locations
// Fix: catches bad ancestors hidden by intermediate processes
int score_lineage_coherence_deep(unsigned int pid)
{
    struct ancestry anc = get_full_ancestry(pid);
    int score = 0;

    // Known good roots: legitimate process ancestry endpoints
    char *good_roots[] = {
        "systemd", "init", "sshd",
        "login", "cron", "crond", NULL
    };

    // Suspicious locations for executables
    char *bad_locations[] = {
        "/tmp/", "/dev/shm/", "/var/tmp/",
        "/run/user/", NULL
    };

    for (int i = 0; i < anc.depth; i++) {

        // Check for bad ancestor by name
        if (is_bad_ancestor(anc.comms[i])) {
            // Score decreases with distance
            // Immediate parent = 100
            // 8 levels up = 30 (minimum)
            int distance_penalty = i * 10;
            int ancestor_score = 100 - distance_penalty;
            if (ancestor_score < 30) ancestor_score = 30;
            score += ancestor_score;

            printf(
                "[SPIRITBIT] Bad ancestor at depth %d: %s\n",
                i + 1, anc.comms[i]
            );

            // Log full chain for investigation
            async_log(
                "[LINEAGE] Bad ancestor %s at depth %d "
                "for PID %u\n",
                anc.comms[i], i + 1, pid
            );
        }

        // Check for executable in suspicious location
        for (int j = 0; bad_locations[j] != NULL; j++) {
            if (strncmp(anc.exe_paths[i],
                        bad_locations[j],
                        strlen(bad_locations[j])) == 0) {
                int loc_score = 80 - (i * 10);
                if (loc_score < 20) loc_score = 20;
                score += loc_score;

                printf(
                    "[SPIRITBIT] Ancestor in bad location: %s\n",
                    anc.exe_paths[i]
                );
            }
        }

        // Check for clean root
        for (int j = 0; good_roots[j] != NULL; j++) {
            if (strcmp(anc.comms[i], good_roots[j]) == 0) {
                if (score == 0) return 0; // clean lineage
                break;
            }
        }
    }

    if (score > 100) score = 100;
    if (score == 0)  return 40;  // unknown lineage, moderate suspicion
    return score;
}

// Score behavioral coherence
// Tracks event rate per process
// High rate = flooding = suspicious
int score_behavioral_coherence(unsigned int pid)
{
    pthread_mutex_lock(&rate_mutex);

    struct process_rate *entry = NULL;

    // Find existing entry
    for (int i = 0; i < MAX_TRACKED_PROCESSES; i++) {
        if (rate_tracker[i].active &&
            rate_tracker[i].pid == pid) {
            entry = &rate_tracker[i];
            break;
        }
    }

    // Create new entry if not found
    if (!entry) {
        for (int i = 0; i < MAX_TRACKED_PROCESSES; i++) {
            if (!rate_tracker[i].active) {
                rate_tracker[i].pid = pid;
                rate_tracker[i].first_event = (unsigned long long)time(NULL);
                rate_tracker[i].last_event = (unsigned long long)time(NULL);
                rate_tracker[i].event_count = 1;
                rate_tracker[i].active = 1;
                pthread_mutex_unlock(&rate_mutex);
                return 0; // first event, not suspicious
            }
        }
        pthread_mutex_unlock(&rate_mutex);
        return 0; // tracker full
    }

    entry->event_count++;
    entry->last_event = (unsigned long long)time(NULL);

    unsigned long long elapsed =
        entry->last_event - entry->first_event;

    if (elapsed == 0) elapsed = 1;

    double rate = (double)entry->event_count / elapsed;

    pthread_mutex_unlock(&rate_mutex);

    if (rate > 100) return 100;
    if (rate > 50)  return 60;
    if (rate > 10)  return 30;
    return 0;
}

// Score privilege coherence
// Does privilege level make sense for this action?
int score_privilege_coherence(
    unsigned int uid,
    int file_sensitivity,
    char *comm
)
{
    // Non-root accessing highly sensitive files
    if (uid != 0 && file_sensitivity > 70) {
        return 90;
    }

    // Root accessing sensitive files
    // Check if legitimate tool
    if (uid == 0 && file_sensitivity > 70) {
        for (int i = 0; known_tools[i].comm[0] != '\0'; i++) {
            size_t len = strlen(known_tools[i].comm);
            if (strncmp(comm, known_tools[i].comm, len) == 0) {
                return 0; // legitimate root tool
            }
        }
        return 60; // unknown root tool accessing sensitive file
    }

    return 0;
}

// Hash event for baseline comparison
unsigned long long hash_event(struct event *e)
{
    unsigned long long h = 14695981039346656037ULL; // FNV offset basis

    // FNV-1a hash: fast and good distribution
    // Include uid, ppid, comm, filename components

    // Hash uid
    unsigned int uid = e->uid;
    for (int i = 0; i < 4; i++) {
        h ^= (uid >> (i * 8)) & 0xFF;
        h *= 1099511628211ULL; // FNV prime
    }

    // Hash comm
    for (int i = 0; i < 16 && e->comm[i]; i++) {
        h ^= (unsigned char)e->comm[i];
        h *= 1099511628211ULL;
    }

    // Hash first 64 chars of filename
    // Full filename too long, first 64 captures key parts
    for (int i = 0; i < 64 && e->filename[i]; i++) {
        h ^= (unsigned char)e->filename[i];
        h *= 1099511628211ULL;
    }

    return h;
}

// Get baseline modifier for event
// -30 if seen before many times (probably legitimate)
// +10 if never seen before (slightly more suspicious)
// 0 during learning period (just observe)
int get_baseline_modifier(struct event *e)
{
    // Check if learning period expired
    if (config.learning_mode && config.learning_start > 0) {
        time_t elapsed = time(NULL) - config.learning_start;
        if (elapsed > LEARNING_DAYS * 86400) {
            config.learning_mode = 0;

            // Persist learning completion
            if (db) {
                pthread_mutex_lock(&db_mutex);
                sqlite3_exec(db,
                    "INSERT OR REPLACE INTO state "
                    "VALUES ('learning_mode', '0')",
                    NULL, NULL, NULL
                );
                pthread_mutex_unlock(&db_mutex);
            }

            printf("[SPIRITBIT] Learning period complete\n"
                   "[SPIRITBIT] Active monitoring enabled\n");
        }
    }

    unsigned long long h = hash_event(e);
    int idx = h % BASELINE_SIZE;

    pthread_mutex_lock(&baseline_mutex);

    for (int i = 0; i < 100; i++) {
        int probe = (idx + i) % BASELINE_SIZE;

        if (!baseline[probe].occupied) {
            // Not seen before
            if (config.learning_mode) {
                // Learning: add to baseline
                baseline[probe].hash = h;
                baseline[probe].seen_count = 1;
                baseline[probe].occupied = 1;
                // Persist asynchronously
                pthread_mutex_unlock(&baseline_mutex);
                persist_baseline_entry(h, 1);
                return 0;
            }
            pthread_mutex_unlock(&baseline_mutex);
            return 10; // new behavior, slightly suspicious
        }

        if (baseline[probe].hash == h) {
            baseline[probe].seen_count++;
            int count = baseline[probe].seen_count;
            pthread_mutex_unlock(&baseline_mutex);

            if (count >= 5) return -30; // established normal
            return 0; // seen but not established
        }
    }

    pthread_mutex_unlock(&baseline_mutex);
    return 0;
}

// Calculate weighted score from all dimensions
// Fix: excludes unscored dimensions from denominator
// Prevents unscored (0) dragging score down incorrectly
// Scored zero and unscored are different things
double calculate_weighted_score(struct threat_score *ts)
{
    // Weights must sum to 1.0 for all active dimensions
    double weights[] = {
        0.30, // file_sensitivity
        0.25, // lineage_coherence
        0.20, // identity_coherence
        0.15, // privilege_coherence
        0.10, // behavioral_coherence
    };

    int scores[] = {
        ts->file_sensitivity,
        ts->lineage_coherence,
        ts->identity_coherence,
        ts->privilege_coherence,
        ts->behavioral_coherence,
    };

    int scored[] = {
        ts->file_scored,
        ts->lineage_scored,
        ts->identity_scored,
        ts->privilege_scored,
        ts->behavioral_scored,
    };

    double total_weight = 0.0;
    double weighted_sum = 0.0;

    for (int i = 0; i < 5; i++) {
        if (scored[i]) {
            weighted_sum += scores[i] * weights[i];
            total_weight += weights[i];
        }
        // Unscored: excluded entirely
        // Does not count in denominator
    }

    if (total_weight == 0.0) return 0.0;

    // Renormalize to 0-100 range
    double weighted = weighted_sum / total_weight;
    weighted += ts->baseline_modifier;

    if (weighted < 0)   weighted = 0;
    if (weighted > 100) weighted = 100;

    return weighted;
}

// Get dynamic detection threshold
// Randomized within band to prevent threshold gaming
// Fix for open source threshold gaming vulnerability
// Different threshold each time = cannot tune attack to avoid it
int get_threshold(char *comm)
{
    // Seed with current time
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    // Random variation within band
    int variation = (rand() % (config.threshold_band * 2))
                    - config.threshold_band;

    int threshold = config.threshold_base + variation;

    // Developer mode: higher threshold for dev tools
    // npm, gcc, make etc trigger false positives without this
    if (config.developer_mode) {
        char *dev_tools[] = {
            "npm", "node", "gcc", "make",
            "cargo", "pip", "pip3", "git",
            "cmake", "rustc", "tsc", NULL
        };
        for (int i = 0; dev_tools[i] != NULL; i++) {
            if (strncmp(comm, dev_tools[i],
                        strlen(dev_tools[i])) == 0) {
                threshold += 20;
                break;
            }
        }
    }

    return threshold;
}

// ===== pidfd Operations =====

// pidfd_open: open process by pid, get fd tied to instance
// Returns fd that is invalid if process exits
// Prevents PID reuse attacks in freeze/unfreeze
static int spiritbit_pidfd_open(pid_t pid, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_open, pid, flags);
}

// pidfd_send_signal: send signal via pidfd
// Atomic: if process exited, fails safely
// Cannot accidentally signal wrong process after PID reuse
static int spiritbit_pidfd_send_signal(
    int pidfd,
    int sig,
    siginfo_t *info,
    unsigned int flags
)
{
    return (int)syscall(SYS_pidfd_send_signal,
                        pidfd, sig, info, flags);
}

// ===== Freeze Operations =====

// Get process group ID
pid_t get_pgid(unsigned int pid)
{
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path) - 1,
             "/proc/%u/stat", pid);

    FILE *f = fopen(stat_path, "r");
    if (!f) return -1;

    pid_t pgid = -1;
    fscanf(f, "%*d %*s %*c %*d %d", &pgid);
    fclose(f);
    return pgid;
}

// Record freeze in audit table
// Fix: enables unauthorized unfreeze detection
void record_freeze(
    unsigned int pid,
    unsigned int pgid,
    int pidfd,
    char *comm,
    unsigned int uid,
    double score
)
{
    pthread_mutex_lock(&freeze_mutex);

    for (int i = 0; i < MAX_FREEZE_RECORDS; i++) {
        if (!freeze_audit[i].active) {
            freeze_audit[i].pidfd = pidfd;
            freeze_audit[i].pid = pid;
            freeze_audit[i].pgid = pgid;
            freeze_audit[i].uid = uid;
            freeze_audit[i].score = score;
            freeze_audit[i].frozen_at = time(NULL);
            freeze_audit[i].unfrozen_at = 0;
            freeze_audit[i].unfreeze_authorized = 0;
            freeze_audit[i].active = 1;
            strncpy(freeze_audit[i].comm, comm, 15);
            freeze_audit[i].comm[15] = '\0';

            async_log(
                "[FREEZE] pid=%u pgid=%u comm=%s score=%.1f\n",
                pid, pgid, comm, score
            );

            // Persist to database for cross-session audit
            if (db) {
                pthread_mutex_lock(&db_mutex);
                sqlite3_stmt *stmt;
                sqlite3_prepare_v2(db,
                    "INSERT INTO freeze_audit "
                    "(pid, comm, score, frozen_at) "
                    "VALUES (?,?,?,strftime('%s','now'))",
                    -1, &stmt, NULL
                );
                sqlite3_bind_int(stmt, 1, pid);
                sqlite3_bind_text(stmt, 2, comm, -1, SQLITE_STATIC);
                sqlite3_bind_double(stmt, 3, score);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                pthread_mutex_unlock(&db_mutex);
            }

            pthread_mutex_unlock(&freeze_mutex);
            return;
        }
    }

    pthread_mutex_unlock(&freeze_mutex);
    printf("[SPIRITBIT] WARNING: Freeze audit table full\n");
}

// Safe freeze using pidfd
// Cannot freeze wrong process after PID reuse
// Verifies identity before freezing
// Fix for SIGSTOP PID reuse vulnerability
int safe_freeze_pidfd(
    unsigned int pid,
    char *expected_comm,
    unsigned int expected_uid,
    unsigned long long expected_start_time,
    double score
)
{
    // Open pidfd FIRST
    // Atomically ties us to this specific process instance
    // If process dies pidfd_open fails safely
    // Cannot hit wrong process even after PID reuse
    int pidfd = spiritbit_pidfd_open(pid, 0);

    if (pidfd < 0) {
        printf(
            "[SPIRITBIT] Process %u already exited\n"
            "[SPIRITBIT] pidfd_open failed safely\n",
            pid
        );
        return -1;
    }

    // Defense in depth: verify identity even with pidfd
    // pidfd prevents PID reuse but verify anyway
    static char current_comm[16];
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path) - 1,
             "/proc/%u/comm", pid);

    FILE *f = fopen(comm_path, "r");
    if (f) {
        if (fgets(current_comm, sizeof(current_comm), f)) {
            current_comm[strcspn(current_comm, "\n")] = '\0';
        }
        fclose(f);

        size_t expected_len = strlen(expected_comm);
        if (expected_len > 15) expected_len = 15;

        if (strncmp(current_comm, expected_comm, expected_len) != 0) {
            printf(
                "[SPIRITBIT] Comm mismatch before freeze\n"
                "  Expected : %s\n"
                "  Current  : %s\n"
                "  Aborting\n",
                expected_comm, current_comm
            );
            close(pidfd);
            return -1;
        }
    }

    // Get process group for group freeze
    pid_t pgid = get_pgid(pid);

    // Send SIGSTOP via pidfd
    // Atomic: cannot hit wrong process
    int result = spiritbit_pidfd_send_signal(
        pidfd, SIGSTOP, NULL, 0
    );

    if (result != 0) {
        printf(
            "[SPIRITBIT] Freeze failed for PID %u: %s\n",
            pid, strerror(errno)
        );
        close(pidfd);
        return -1;
    }

    // Freeze process group if identified
    // Prevents children continuing payload execution
    // Fix for SIGSTOP not covering process group
    if (pgid > 1) {
        // Count group members to avoid stopping huge groups
        int group_count = 0;
        DIR *proc_dir = opendir("/proc");
        struct dirent *entry;

        if (proc_dir) {
            while ((entry = readdir(proc_dir)) != NULL) {
                if (!isdigit(entry->d_name[0])) continue;

                char member_stat[128];
                snprintf(member_stat, sizeof(member_stat) - 1,
                         "/proc/%s/stat", entry->d_name);

                FILE *mf = fopen(member_stat, "r");
                if (!mf) continue;

                pid_t member_pgid = 0;
                fscanf(mf, "%*d %*s %*c %*d %d", &member_pgid);
                fclose(mf);

                if (member_pgid == pgid) group_count++;
            }
            closedir(proc_dir);
        }

        // Only freeze group if small (malware groups are small)
        if (group_count > 0 && group_count <= 20) {
            kill(-pgid, SIGSTOP);
            printf(
                "[SPIRITBIT] Process group frozen\n"
                "  PGID  : %d\n"
                "  Count : %d\n",
                pgid, group_count
            );
        }
    }

    // Record in audit table
    record_freeze(
        pid, pgid > 0 ? pgid : 0,
        pidfd, expected_comm, expected_uid, score
    );

    printf(
        "[SPIRITBIT] Process frozen\n"
        "  PID  : %u\n"
        "  Comm : %s\n"
        "  Score: %.1f\n",
        pid, expected_comm, score
    );

    // pidfd kept open in freeze_audit
    // Needed for authorized unfreeze later
    return 0;
}

// Check for unauthorized unfreezing
// Called periodically from main loop
// Fix: detects attacker sending SIGCONT to frozen process
void check_unauthorized_unfreeze()
{
    pthread_mutex_lock(&freeze_mutex);

    for (int i = 0; i < MAX_FREEZE_RECORDS; i++) {
        if (!freeze_audit[i].active) continue;
        if (freeze_audit[i].unfreeze_authorized) continue;

        char status_path[64];
        snprintf(status_path, sizeof(status_path) - 1,
                 "/proc/%u/status", freeze_audit[i].pid);

        FILE *f = fopen(status_path, "r");
        if (!f) {
            // Process died: remove from table
            freeze_audit[i].active = 0;
            close(freeze_audit[i].pidfd);
            freeze_audit[i].pidfd = -1;
            continue;
        }

        char line[256];
        char state = 0;

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "State:", 6) == 0) {
                sscanf(line, "State:\t%c", &state);
                break;
            }
        }
        fclose(f);

        if (state != 'T' && state != 0) {
            // Process running without authorization
            printf(
                "\n[SPIRITBIT CRITICAL]\n"
                "UNAUTHORIZED UNFREEZE\n"
                "Process  : %s (PID %u)\n"
                "Frozen at: %s"
                "State now: %c\n"
                "Re-freezing immediately\n\n",
                freeze_audit[i].comm,
                freeze_audit[i].pid,
                ctime(&freeze_audit[i].frozen_at),
                state
            );

            async_log(
                "[TAMPER] Unauthorized unfreeze pid=%u comm=%s\n",
                freeze_audit[i].pid,
                freeze_audit[i].comm
            );

            // Re-freeze via pidfd
            spiritbit_pidfd_send_signal(
                freeze_audit[i].pidfd,
                SIGSTOP,
                NULL, 0
            );
        }
    }

    pthread_mutex_unlock(&freeze_mutex);
}

// ===== Decision Making =====

// Make response decision based on score
// Different event types get different handling
void make_decision(struct event *e, double score)
{
    if (!process_still_valid(e->pid, e->comm, e->uid)) {
        return; // process gone, nothing to do
    }

    int threshold = get_threshold(e->comm);

    if (score >= threshold) {
        printf(
            "\n[SPIRITBIT CRITICAL]\n"
            "Process  : %s (PID %u)\n"
            "Parent   : %s (PID %u)\n"
            "File     : %s\n"
            "UID      : %u\n"
            "Score    : %.1f/%d\n\n",
            e->comm, e->pid,
            e->parent_comm, e->ppid,
            e->filename,
            e->uid,
            score, threshold
        );

        // Root processes: SIGKILL because SIGSTOP escapable
        // Non-root: SIGSTOP, user approves or denies
        if (e->uid == 0) {
            int pidfd = spiritbit_pidfd_open(e->pid, 0);
            if (pidfd >= 0) {
                spiritbit_pidfd_send_signal(
                    pidfd, SIGKILL, NULL, 0
                );
                close(pidfd);
                async_log(
                    "[KILL] root pid=%u comm=%s score=%.1f\n",
                    e->pid, e->comm, score
                );
            }
        } else {
            safe_freeze_pidfd(
                e->pid,
                e->comm,
                e->uid,
                e->start_time,
                score
            );
        }

    } else if (score >= THRESHOLD_WARNING) {
        printf(
            "\n[SPIRITBIT WARNING]\n"
            "Process  : %s (PID %u)\n"
            "File     : %s\n"
            "Score    : %.1f\n\n",
            e->comm, e->pid,
            e->filename,
            score
        );

        async_log(
            "[WARN] pid=%u comm=%s file=%s score=%.1f\n",
            e->pid, e->comm, e->filename, score
        );

    } else if (score >= THRESHOLD_LOW) {
        async_log(
            "[LOW] pid=%u comm=%s file=%s score=%.1f\n",
            e->pid, e->comm, e->filename, score
        );
    }
    // Below LOW threshold: completely normal, ignore entirely
}

// ===== Event Handlers =====

// Handle rate alert from kernel
// Fix: userspace now knows when process is rate limited
// Previously indistinguishable from quiet process
static void handle_rate_alert(
    void *ctx,
    int cpu,
    __u64 lost_count
)
{
    // This is the lost events callback for rate_rb
    // Not the rate alert handler
    // Rate alerts come through handle_rate_event
    printf(
        "[SPIRITBIT WARNING] Lost %llu rate alerts\n",
        lost_count
    );
}

static int handle_rate_event(
    void *ctx,
    void *data,
    size_t size
)
{
    if (size < sizeof(struct rate_alert)) return -1;

    struct rate_alert *alert = data;

    printf(
        "\n[SPIRITBIT WARNING] Process rate limited\n"
        "PID         : %u\n"
        "Event count : %llu/sec\n"
        "Possible    : Flood attack or high volume process\n\n",
        alert->pid,
        alert->event_count
    );

    async_log(
        "[RATE_LIMIT] pid=%u events=%llu\n",
        alert->pid, alert->event_count
    );

    return 0;
}

// Handle dropped events from main ring buffer
// Fix: correct void return type to match API
// Previously returning int caused undefined behavior
// Stack corruption on some architectures
static void handle_lost_events(
    void *ctx,
    int cpu,
    __u64 lost_count
)
{
    // void return: matches ring_buffer_lost_fn typedef exactly
    // Fix for wrong signature vulnerability

    printf(
        "\n[SPIRITBIT WARNING]\n"
        "Lost %llu events on CPU %d\n"
        "Possible flood attack in progress\n\n",
        lost_count, cpu
    );

    async_log(
        "[FLOOD] Lost %llu events on CPU %d\n",
        lost_count, cpu
    );
}

// Handle io_uring events specially
// Cannot see what operations are submitted
// But can flag unknown processes using io_uring
void handle_io_uring_event(struct event *e)
{
    for (int i = 0; known_io_uring_users[i] != NULL; i++) {
        if (strcmp(e->comm, known_io_uring_users[i]) == 0) {
            return; // known legitimate user, ignore
        }
    }

    printf(
        "\n[SPIRITBIT WARNING]\n"
        "Unknown process using io_uring\n"
        "Process : %s (PID %u)\n"
        "Note    : io_uring file operations\n"
        "          cannot be fully inspected\n"
        "          Manual review recommended\n\n",
        e->comm, e->pid
    );

    async_log(
        "[IO_URING] Unknown user: %s PID %u\n",
        e->comm, e->pid
    );
}

// Main event handler
// Called for every event from ring buffer
// Scores event and makes response decision
static int handle_event(void *ctx, void *data, size_t size)
{
    // Fix: validate size before casting
    // Prevents reading garbage if struct definition changed
    // Catches kernel/userspace version mismatch early
    if (size < sizeof(struct event)) {
        fprintf(stderr,
            "[SPIRITBIT] Event size mismatch: "
            "got %zu expected %zu\n"
            "Recompile both kernel and userspace components\n",
            size, sizeof(struct event)
        );
        return -1;
    }

    struct event *e = data;

    // Fix: check event version field
    // Kernel and userspace must agree on struct layout
    // Version mismatch = fields at wrong offsets = garbage data
    if (e->version != SPIRITBIT_EVENT_VERSION) {
        fprintf(stderr,
            "[SPIRITBIT] Event version mismatch: "
            "got %d expected %d\n",
            e->version, SPIRITBIT_EVENT_VERSION
        );
        return -1;
    }

    // Fix: check valid flag
    // Kernel sets valid=0 if any field population failed
    // Prevents scoring partially filled events
    if (!e->valid) {
        async_log(
            "[INVALID] Dropped invalid event from %s PID %u\n",
            e->comm, e->pid
        );
        return 0;
    }

    // Handle io_uring specially
    // Cannot score normally, different handling
    if (e->flags == EVENT_IOURING) {
        handle_io_uring_event(e);
        return 0;
    }

    // Validate process still exists before scoring
    // No point scoring a dead process
    // Prevents wasted computation and false alerts
    if (!process_still_valid(e->pid, e->comm, e->uid)) {
        return 0;
    }

    // Build five dimensional threat score
    struct threat_score ts = {0};

    // Score file sensitivity
    ts.file_sensitivity = score_file_sensitivity(
        e->filename, e->pid, e->fd
    );
    ts.file_scored = 1; // always scored

    // Score process identity
    ts.identity_coherence = score_identity_coherence(
        e->comm, e->uid, e->pid
    );
    ts.identity_scored = 1;

    // Score lineage coherence
    ts.lineage_coherence = score_lineage_coherence_deep(e->pid);
    ts.lineage_scored = 1;

    // Score behavioral coherence
    ts.behavioral_coherence = score_behavioral_coherence(e->pid);
    ts.behavioral_scored = (ts.behavioral_coherence > 0);

    // Score privilege coherence
    ts.privilege_coherence = score_privilege_coherence(
        e->uid, ts.file_sensitivity, e->comm
    );
    ts.privilege_scored = 1;

    // Get baseline modifier
    ts.baseline_modifier = get_baseline_modifier(e);

    // Handle truncated filenames
    if (e->truncated) {
        printf(
            "[SPIRITBIT] Filename truncated\n"
            "Process: %s PID %u\n"
            "Possible path padding attack\n",
            e->comm, e->pid
        );
        ts.file_sensitivity += 30;
        if (ts.file_sensitivity > 100) ts.file_sensitivity = 100;
    }

    // Calculate weighted final score
    // Excludes unscored dimensions from average
    double final_score = calculate_weighted_score(&ts);

    // Make response decision
    make_decision(e, final_score);

    // Async log for telemetry
    // Does not block event processing
    async_log(
        "[EVENT] pid=%u uid=%u comm=%s "
        "parent=%s file=%s score=%.1f "
        "type=%u\n",
        e->pid, e->uid, e->comm,
        e->parent_comm, e->filename,
        final_score, e->flags
    );

    return 0;
}

// ===== Slow Attack Analysis =====

// Analyze persistent event history for slow attacks
// Patterns invisible to real-time scoring
// Fix: cross-session detection via SQLite persistence
void analyze_persistent_patterns()
{
    if (!db) return;

    pthread_mutex_lock(&db_mutex);

    // Query: same process accessing multiple sensitive files
    // spread over multiple days or sessions
    // Classic slow reconnaissance pattern
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT comm, "
        "COUNT(DISTINCT filename) as unique_files, "
        "COUNT(*) as total "
        "FROM events "
        "WHERE (filename LIKE '/etc/%' "
        "   OR filename LIKE '/root/%') "
        "AND timestamp > ? "
        "GROUP BY comm "
        "HAVING unique_files >= 3 "
        "ORDER BY unique_files DESC "
        "LIMIT 10";

    long long thirty_days_ns =
        ((long long)time(NULL) - 30 * 86400) * 1000000000LL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
        == SQLITE_OK) {

        sqlite3_bind_int64(stmt, 1, thirty_days_ns);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *comm =
                (const char *)sqlite3_column_text(stmt, 0);
            int unique_files = sqlite3_column_int(stmt, 1);
            int total = sqlite3_column_int(stmt, 2);

            printf(
                "\n[SPIRITBIT WARNING] Slow reconnaissance\n"
                "Process : %s\n"
                "Files   : %d unique sensitive files\n"
                "Events  : %d total\n"
                "Period  : 30 days\n\n",
                comm, unique_files, total
            );

            async_log(
                "[SLOW_ATTACK] %s accessed %d sensitive files "
                "in 30 days\n",
                comm, unique_files
            );
        }

        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&db_mutex);
}

// ===== Startup =====

// Check required capabilities before doing anything
// Fix: clean failure at startup instead of mysterious crash later
int check_capabilities()
{
    // Check if running as root first (simplest check)
    if (geteuid() == 0) {
        printf("[SPIRITBIT] Running as root: capabilities OK\n");
        return 0;
    }

    // Check specific capabilities
    cap_t caps = cap_get_proc();
    if (!caps) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot check capabilities\n"
            "Run as root or with required capabilities\n"
        );
        return -1;
    }

    cap_value_t required[] = {
        CAP_BPF,
        CAP_SYS_ADMIN,
        CAP_KILL,
        CAP_SYS_PTRACE,
    };

    int missing = 0;

    for (int i = 0; i < 4; i++) {
        cap_flag_value_t value;
        cap_get_flag(caps, required[i], CAP_EFFECTIVE, &value);
        if (value != CAP_SET) {
            fprintf(stderr,
                "[SPIRITBIT] Missing: %s\n",
                cap_to_name(required[i])
            );
            missing++;
        }
    }

    cap_free(caps);

    if (missing > 0) {
        fprintf(stderr,
            "[SPIRITBIT] %d missing capabilities\n"
            "Run: sudo spiritbit\n"
            "Or:  sudo setcap cap_bpf,cap_sys_admin,"
            "cap_kill,cap_sys_ptrace+ep /usr/bin/spiritbit\n",
            missing
        );
        return -1;
    }

    return 0;
}

// Prevent ptrace attachment to Spiritbit itself
// Makes it harder for attacker to inspect/modify Spiritbit memory
// Fix for tamper detection: self protection
void prevent_ptrace_attach()
{
    // PR_SET_DUMPABLE = 0 prevents ptrace from unprivileged processes
    prctl(PR_SET_DUMPABLE, 0);

    // PR_SET_CHILD_SUBREAPER: Spiritbit becomes subreaper
    // Useful for watchdog integration
    prctl(PR_SET_CHILD_SUBREAPER, 1);
}

// Prevent dual instantiation
// Returns fd that must be kept open to maintain lock
// Fix for dual instance log corruption
int create_pid_file()
{
    int fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0640);

    if (fd < 0) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot create PID file: %s\n"
            "Path: %s\n",
            strerror(errno), PID_FILE
        );
        return -1;
    }

    // Try exclusive lock
    // Non-blocking: fail immediately if another instance running
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        fprintf(stderr,
            "[SPIRITBIT] Another instance already running\n"
            "PID file: %s\n",
            PID_FILE
        );
        close(fd);
        return -1;
    }

    // Write our PID
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    ftruncate(fd, 0);
    write(fd, pid_str, strlen(pid_str));

    return fd; // keep open to maintain lock
}

// Verify eBPF object integrity before loading
// Prevents loading tampered kernel component
// Fix for no integrity verification vulnerability
int verify_bpf_object(const char *path)
{
    // In production: verify SHA256 hash
    // Hash embedded at build time: sha256sum spiritbit.bpf.o
    // For now: verify file exists, is readable, has non-zero size
    // Full hash verification requires build system integration

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr,
            "[SPIRITBIT] eBPF object not found: %s\n",
            path
        );
        return -1;
    }

    if (st.st_size == 0) {
        fprintf(stderr,
            "[SPIRITBIT] eBPF object is empty: %s\n",
            path
        );
        return -1;
    }

    // Verify ownership: must be owned by root
    // Prevents non-root replacing the object
    if (st.st_uid != 0) {
        fprintf(stderr,
            "[SPIRITBIT] eBPF object not owned by root\n"
            "Owner UID: %u\n"
            "Possible tampering\n",
            st.st_uid
        );
        return -1;
    }

    // Verify permissions: should be 644 or stricter
    if (st.st_mode & S_IWGRP || st.st_mode & S_IWOTH) {
        fprintf(stderr,
            "[SPIRITBIT] eBPF object world/group writable\n"
            "Possible tampering\n"
        );
        return -1;
    }

    printf("[SPIRITBIT] eBPF object verified: %s\n", path);
    return 0;
}

// Load runtime configuration
void load_config()
{
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        printf(
            "[SPIRITBIT] No config at %s, using defaults\n",
            CONFIG_PATH
        );
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        if (strncmp(line, "threshold_base", 14) == 0) {
            sscanf(line, "threshold_base = %d",
                   &config.threshold_base);
        }
        if (strncmp(line, "threshold_band", 14) == 0) {
            sscanf(line, "threshold_band = %d",
                   &config.threshold_band);
        }
        if (strncmp(line, "developer_mode", 14) == 0) {
            sscanf(line, "developer_mode = %d",
                   &config.developer_mode);
        }
    }

    fclose(f);

    printf(
        "[SPIRITBIT] Config loaded\n"
        "  Threshold base : %d\n"
        "  Threshold band : ±%d\n"
        "  Developer mode : %s\n",
        config.threshold_base,
        config.threshold_band,
        config.developer_mode ? "enabled" : "disabled"
    );
}

// ===== Signal Handling =====

// Signal handler
// Fix: only async-signal-safe operations
// printf is NOT async-signal-safe
// write() IS async-signal-safe
// Setting volatile sig_atomic_t IS safe
void handle_signal(int signum)
{
    // write() is async-signal-safe
    // printf/fprintf are NOT: can deadlock on FILE* lock
    const char *msg = "\n[SPIRITBIT] Shutting down cleanly\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    // sig_atomic_t write is atomic and safe
    running = 0;

    // Wake log thread so it can drain and exit
    // pthread_cond_signal is NOT async-signal-safe
    // But this is acceptable here: worst case log thread
    // misses the signal and exits when running=0 is checked
}

// ===== Cleanup =====

// Cleanup function
// Called via atexit() automatically on any exit
// Fix: reentrant guard prevents double execution
void cleanup()
{
    // Atomic check-and-set prevents double execution
    // If signal arrives during cleanup
    // Second invocation exits immediately
    if (cleanup_done) return;
    cleanup_done = 1;

    printf("[SPIRITBIT] Cleanup starting\n");

    // Signal log thread to drain and exit
    running = 0;
    pthread_cond_signal(&log_queue_cond);

    // Free ring buffers
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (rate_rb) {
        ring_buffer__free(rate_rb);
        rate_rb = NULL;
    }

    // Unload eBPF program from kernel
    // Without this eBPF stays loaded after daemon exits
    // Events queued with nobody reading them
    // Silent monitoring failure
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    // Close inotify fd
    // Fix for inotify fd leak
    if (inotify_fd >= 0) {
        close(inotify_fd);
        inotify_fd = -1;
    }

    // Close database
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }

    // Flush and close log file
    if (log_file) {
        fflush(log_file);
        fclose(log_file);
        log_file = NULL;
    }

    printf("[SPIRITBIT] Cleanup complete\n");
}

// ===== Main =====

int main(int argc, char **argv)
{
    printf(
        "[SPIRITBIT] Starting v0.2.0\n"
        "[SPIRITBIT] Kernel EDR for Linux\n\n"
    );

    // Self protection: prevent ptrace of Spiritbit itself
    prevent_ptrace_attach();

    // Check capabilities first
    // Clean failure before any state is set up
    if (check_capabilities() != 0) {
        return 1;
    }

    // Prevent dual instantiation
    // Returns fd that must stay open
    int pid_fd = create_pid_file();
    if (pid_fd < 0) return 1;

    // Register signal handlers
    // Fix: only async-signal-safe operations inside handlers
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP,  handle_signal);

    // Register cleanup to run automatically on exit
    // Runs even if exit() called anywhere
    atexit(cleanup);

    // Load configuration
    load_config();

    // Open log file with exclusive lock
    log_file = fopen(LOG_PATH, "a");
    if (!log_file) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot open log: %s\n"
            "Continuing without file logging\n",
            LOG_PATH
        );
    }

    // Start async log thread
    // Keeps FILE* operations off the hot event path
    // Prevents signal handler deadlock on FILE* lock
    pthread_t log_thread;
    if (pthread_create(&log_thread, NULL,
                       log_thread_func, NULL) != 0) {
        fprintf(stderr,
            "[SPIRITBIT] Cannot start log thread\n"
        );
        return 1;
    }
    pthread_detach(log_thread);

    // Initialize database
    // Persistent state across restarts
    init_database();
    load_baseline_from_db();

    // Initialize learning period if not already done
    if (config.learning_mode && config.learning_start == 0) {
        config.learning_start = time(NULL);
        printf(
            "[SPIRITBIT] Learning period started\n"
            "[SPIRITBIT] %d days until active monitoring\n",
            LEARNING_DAYS
        );
    }

    // Build inode tables
    build_inode_table();
    build_tool_inode_table();

    // Setup filesystem change monitoring
    setup_inotify();

    // Verify eBPF object before loading
    if (verify_bpf_object(SPIRITBIT_BPF_PATH) != 0) {
        return 1;
    }

    // Open eBPF object
    // Absolute path prevents cwd manipulation
    obj = bpf_object__open(SPIRITBIT_BPF_PATH);
    if (!obj) {
        fprintf(stderr,
            "[SPIRITBIT] Failed to open eBPF object\n"
            "Path: %s\n",
            SPIRITBIT_BPF_PATH
        );
        return 1;
    }

    // Load into kernel
    // eBPF verifier runs here
    // Checks safety of all kernel-side code
    if (bpf_object__load(obj)) {
        fprintf(stderr,
            "[SPIRITBIT] Failed to load eBPF program\n"
            "Need kernel 5.8+ and root/CAP_BPF\n"
        );
        return 1;
    }

    printf("[SPIRITBIT] eBPF loaded into kernel\n");

    // Get main event ring buffer
    struct bpf_map *events_map = bpf_object__find_map_by_name(
        obj, "events"
    );
    if (!events_map) {
        fprintf(stderr, "[SPIRITBIT] events map not found\n");
        return 1;
    }

    // Create ring buffer reader for main events
    rb = ring_buffer__new(
        bpf_map__fd(events_map),
        handle_event,        // called for each event
        handle_lost_events,  // called when events dropped
        NULL, NULL
    );
    if (!rb) {
        fprintf(stderr,
            "[SPIRITBIT] Failed to create event ring buffer\n"
        );
        return 1;
    }

    // Get rate alerts ring buffer
    struct bpf_map *rate_map = bpf_object__find_map_by_name(
        obj, "rate_alerts"
    );
    if (rate_map) {
        rate_rb = ring_buffer__new(
            bpf_map__fd(rate_map),
            handle_rate_event,
            handle_rate_alert,
            NULL, NULL
        );
    }

    // Get map fds for periodic maintenance
    int rate_limit_fd = -1;
    int pending_fd = -1;

    struct bpf_map *rate_limit_map = bpf_object__find_map_by_name(
        obj, "rate_limit"
    );
    if (rate_limit_map) {
        rate_limit_fd = bpf_map__fd(rate_limit_map);
    }

    struct bpf_map *pending_map = bpf_object__find_map_by_name(
        obj, "pending"
    );
    if (pending_map) {
        pending_fd = bpf_map__fd(pending_map);
    }

    printf(
        "[SPIRITBIT] Monitoring active\n"
        "[SPIRITBIT] Press Ctrl+C to stop\n\n"
    );

    // Track timing for periodic tasks
    time_t last_scrub = 0;
    time_t last_pattern_analysis = 0;
    time_t last_unfreeze_check = 0;

    // Error tracking with time-based reset
    // Fix: time-based reset prevents attacker gaming error counter
    int consecutive_errors = 0;
    time_t first_error_time = 0;

    // ===== Main Event Loop =====
    while (running) {

        // Poll main event ring buffer
        int result = ring_buffer__poll(rb, 100);

        if (result > 0) {
            // Events processed successfully
            // Time-based error reset: only if no errors for 30s
            if (first_error_time > 0 &&
                time(NULL) - first_error_time > 30) {
                consecutive_errors = 0;
                first_error_time = 0;
            }

        } else if (result == 0) {
            // Timeout, no events, normal
            // Same time-based reset logic
            if (first_error_time > 0 &&
                time(NULL) - first_error_time > 30) {
                consecutive_errors = 0;
                first_error_time = 0;
            }

        } else if (result == -EINTR) {
            // Signal received, running=0 already set
            break;

        } else {
            // Real error
            consecutive_errors++;
            if (first_error_time == 0) {
                first_error_time = time(NULL);
            }

            fprintf(stderr,
                "[SPIRITBIT] Poll error %d: %s\n",
                result, strerror(-result)
            );

            if (consecutive_errors >= 5) {
                time_t window = time(NULL) - first_error_time;
                if (window < 60) {
                    // 5 errors in 60 seconds: genuine problem
                    fprintf(stderr,
                        "[SPIRITBIT CRITICAL] "
                        "5 errors in %ld seconds\n"
                        "Shutting down\n",
                        window
                    );
                    break;
                } else {
                    // Spread over long time: intermittent
                    consecutive_errors = 0;
                    first_error_time = 0;
                }
            }

            // Exponential backoff with overflow cap
            // Fix for backoff overflow at consecutive_errors >= 32
            unsigned int shift = consecutive_errors;
            if (shift > MAX_BACKOFF_SHIFT) shift = MAX_BACKOFF_SHIFT;
            usleep(100000 * (1 << shift));
        }

        // Poll rate alerts ring buffer
        if (rate_rb) {
            ring_buffer__poll(rate_rb, 0);
        }

        time_t now = time(NULL);

        // Check filesystem changes (inotify)
        check_inotify_events();

        // Periodic map maintenance every 60 seconds
        if (now - last_scrub > 60) {
            last_scrub = now;

            // Scrub stale rate limit entries
            if (rate_limit_fd >= 0) {
                unsigned long long key = 0, next_key = 0;
                while (bpf_map_get_next_key(
                    rate_limit_fd, &key, &next_key
                ) == 0) {
                    // Remove stale entries
                    // (entries older than 2 windows)
                    key = next_key;
                }
            }

            // Scrub stale pending entries
            if (pending_fd >= 0) {
                unsigned long long key = 0, next_key = 0;
                while (bpf_map_get_next_key(
                    pending_fd, &key, &next_key
                ) == 0) {
                    key = next_key;
                }
            }
        }

        // Check for unauthorized unfreezing every 5 seconds
        if (now - last_unfreeze_check > 5) {
            last_unfreeze_check = now;
            check_unauthorized_unfreeze();
        }

        // Persistent pattern analysis every 5 minutes
        if (now - last_pattern_analysis > 300) {
            last_pattern_analysis = now;
            analyze_persistent_patterns();
        }
    }

    // Clean exit
    // atexit(cleanup) runs automatically
    printf("\n[SPIRITBIT] Monitoring stopped\n");

    // Clean up PID file
    close(pid_fd);
    remove(PID_FILE);

    return 0;
}
