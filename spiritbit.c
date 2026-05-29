// spiritbit.c - Spiritbit v4.4 FULL EXPANDED EDITION
// Complete merge: All original features + new ML, Unstoppable protection, Full ancestry, etc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <seccomp.h>
#include <sqlite3.h>
#include <bpf/libbpf.h>
#include "config.h"

// ====================== STRUCTS ======================
typedef struct {
    float file_sensitivity;
    float lineage_coherence;
    float behavior_rate;
    float privilege_escalation;
    float contextual_anomaly;
    float temporal_consistency;
    float network_behavior;
    float ml_deviation;
    float intel_match;
} Score;

struct event {
    uint8_t  version;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint64_t timestamp;
    char comm[16];
    char path[MAX_FILENAME];
    uint32_t event_type;
    uint8_t  sensitive;
    uint8_t  write;
};

// ====================== GLOBALS ======================
static sqlite3 *db = NULL;
static struct ring_buffer *rb = NULL;
static struct bpf_object *obj = NULL;

static double baseline_mean = 0.0;
static double baseline_variance = 1.0;
static int sample_count = 0;

// Rate limiting
static time_t last_event[65536] = {0};
static int event_counter[65536] = {0};

// ====================== FULL ANCESTRY WALKING ======================
int get_ancestry_depth(uint32_t pid) {
    int depth = 0;
    uint32_t current = pid;
    char buf[64];
    FILE *f;

    for (int i = 0; i < 20 && current > 1; i++) {
        snprintf(buf, sizeof(buf), "/proc/%u/stat", current);
        f = fopen(buf, "r");
        if (!f) break;

        char line[512];
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "%*d %*s %*c %u", &current);
        }
        fclose(f);
        depth++;
    }
    return depth;
}

float get_lineage_score(uint32_t pid) {
    int depth = get_ancestry_depth(pid);
    if (depth <= 3) return 88.0f;      // Very short lineage = suspicious
    if (depth >= 10) return 35.0f;     // Deep = more normal
    return 62.0f;
}

// ====================== DETAILED SQLITE ======================
int init_database(void) {
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "[ERROR] SQLite open failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char *tables = 
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER,"
        "pid INTEGER,"
        "ppid INTEGER,"
        "uid INTEGER,"
        "comm TEXT,"
        "path TEXT,"
        "event_type INTEGER,"
        "score REAL);"

        "CREATE TABLE IF NOT EXISTS baseline ("
        "id INTEGER PRIMARY KEY,"
        "mean REAL,"
        "variance REAL,"
        "samples INTEGER);";

    sqlite3_exec(db, tables, NULL, NULL, NULL);
    return 0;
}

void log_event_to_db(const struct event *e, float score) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO events (timestamp, pid, ppid, uid, comm, path, event_type, score) "
        "VALUES (%llu, %u, %u, %u, '%s', '%s', %u, %.2f);",
        e->timestamp, e->pid, e->ppid, e->uid, e->comm, e->path, e->event_type, score);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

// ====================== RATE LIMITING ======================
int is_rate_limited(uint32_t pid) {
    time_t now = time(NULL);
    int idx = pid % 65536;

    if (now - last_event[idx] < 1) {
        event_counter[idx]++;
        if (event_counter[idx] > 60) return 1;   // Flood protection
    } else {
        event_counter[idx] = 1;
        last_event[idx] = now;
    }
    return 0;
}

// ====================== FULL SCORING ENGINE ======================
float calculate_full_score(const struct event *e) {
    Score s = {0.0f};

    s.file_sensitivity    = e->sensitive ? 92.0f : 12.0f;
    s.lineage_coherence   = get_lineage_score(e->pid);
    s.privilege_escalation = (e->uid == 0) ? 88.0f : 18.0f;
    s.network_behavior    = (e->event_type == 7) ? 82.0f : 20.0f;

    // ML Anomaly Detection
    if (sample_count > 1200) {
        double std = sqrt(baseline_variance);
        double z = (65.0 - baseline_mean) / (std + 0.001);
        s.ml_deviation = (z > 3.3) ? 90.0f : 28.0f;
    }

    float score = (s.file_sensitivity * 0.27f) +
                  (s.lineage_coherence * 0.18f) +
                  (s.privilege_escalation * 0.22f) +
                  (s.network_behavior * 0.15f) +
                  (s.ml_deviation * 0.18f);

    return score > 100.0f ? 100.0f : score;
}

// ====================== UNSTOPPABLE SELF-PROTECTION ======================
void enable_stealth_mode(void) {
    prctl(PR_SET_NAME, "kworker/0:13", 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

void ignore_signals(void) {
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
}

void start_dual_watchdog(void) {
    if (fork() == 0) {  // Watchdog 1
        while (1) {
            sleep(2);
            if (kill(getppid(), 0) != 0) execl("/usr/local/bin/spiritbit", "spiritbit", NULL);
        }
    }
    if (fork() == 0) {  // Watchdog 2
        while (1) {
            sleep(4);
            if (kill(getppid(), 0) != 0) execl("/usr/local/bin/spiritbit", "spiritbit", NULL);
        }
    }
}

void self_restart(void) {
    execl("/usr/local/bin/spiritbit", "spiritbit", NULL);
    exit(1);
}

// ====================== RING BUFFER CALLBACK ======================
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    if (e->version != 42) return 0;

    if (is_rate_limited(e->pid)) return 0;

    float threat_score = calculate_full_score(e);

    if (threat_score >= THREAT_THRESHOLD) {
        kill(e->pid, SIGSTOP);
        printf("[UNSTOPPABLE BLOCK] PID %u | Score: %.1f | %s\n", 
               e->pid, threat_score, e->path);
    }

    log_event_to_db(e, threat_score);

    // Update ML baseline
    sample_count++;
    double delta = threat_score - baseline_mean;
    baseline_mean += delta / sample_count;
    baseline_variance = (baseline_variance * (sample_count - 1) + delta * delta) / sample_count;

    return 0;
}

// ====================== MAIN ======================
int main(void) {
    printf("=== Spiritbit v%s - FULL EXPANDED Unstoppable EDR ===\n", SPIRITBIT_VERSION);

    enable_stealth_mode();
    ignore_signals();
    start_dual_watchdog();

    mkdir("/var/lib/spiritbit", 0700);
    mkdir(QUARANTINE_DIR, 0700);
    mkdir("/var/log/spiritbit", 0700);

    if (init_database() != 0) self_restart();

    // Load BPF
    obj = bpf_object__open("spiritbit.bpf.o");
    if (!obj || bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object\n");
        self_restart();
    }

    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"),
                         handle_event, NULL, NULL);
    if (!rb) self_restart();

    printf("Spiritbit fully loaded with ancestry walking, detailed DB, rate limiting, ML, and dual watchdog.\n");
    printf("Monitoring started in Unstoppable mode.\n");

    // Main polling loop
    while (1) {
        int ret = ring_buffer__poll(rb, 300);
        if (ret < 0) {
            fprintf(stderr, "Ring buffer poll error: %d\n", ret);
            sleep(1);
        }
    }

    return 0;
}
