// spiritbit.c - Spiritbit v4.4 FULL VERSION with 7-Day Learning Period
// All features from original + new improvements

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sqlite3.h>
#include <bpf/libbpf.h>
#include "config.h"

// ====================== STRUCTS ======================
typedef struct {
    float file_sensitivity;
    float lineage_coherence;
    float behavior_rate;
    float privilege_escalation;
    float network_behavior;
    float ml_deviation;
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

static time_t start_time = 0;
static int learning_mode = 1;                    // 1 = Learning (7 days), 0 = Protection

// Rate limiting
static time_t last_event[65536] = {0};
static int event_counter[65536] = {0};

// ====================== 7-DAY LEARNING PERIOD ======================
void check_learning_period(void) {
    if (!learning_mode) return;

    time_t now = time(NULL);
    double elapsed_days = difftime(now, start_time) / (86400.0);  // 86400 = seconds in a day

    if (elapsed_days >= 7.0) {
        learning_mode = 0;
        printf("\n[SPIRITBIT] === 7-DAY LEARNING PERIOD COMPLETED ===\n");
        printf("[SPIRITBIT] Switching to FULL ZERO TRUST PROTECTION MODE\n");
        printf("[SPIRITBIT] Behavioral baseline established.\n");
    } else {
        if (sample_count % 800 == 0) {
            printf("[LEARNING MODE] Day %.2f / 7 | Samples collected: %d\n", 
                   elapsed_days, sample_count);
        }
    }
}

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
    if (depth <= 3) return 88.0f;
    if (depth >= 10) return 35.0f;
    return 62.0f;
}

// ====================== SQLITE ======================
int init_database(void) {
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) return -1;

    const char *schema = 
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp INTEGER, "
        "pid INTEGER, ppid INTEGER, uid INTEGER, comm TEXT, path TEXT, event_type INTEGER, score REAL);";
    
    sqlite3_exec(db, schema, NULL, NULL, NULL);
    return 0;
}

// ====================== RATE LIMITING ======================
int is_rate_limited(uint32_t pid) {
    time_t now = time(NULL);
    int idx = pid % 65536;
    if (now - last_event[idx] < 1) {
        if (++event_counter[idx] > 60) return 1;
    } else {
        event_counter[idx] = 1;
        last_event[idx] = now;
    }
    return 0;
}

// ====================== SCORING ======================
float calculate_full_score(const struct event *e) {
    Score s = {0};

    s.file_sensitivity    = e->sensitive ? 92.0f : 12.0f;
    s.lineage_coherence   = get_lineage_score(e->pid);
    s.privilege_escalation = (e->uid == 0) ? 88.0f : 18.0f;
    s.network_behavior    = (e->event_type == 7) ? 82.0f : 20.0f;

    if (sample_count > 1000) {
        double std = sqrt(baseline_variance);
        double z = (65.0 - baseline_mean) / (std + 0.001);
        s.ml_deviation = (z > 3.3) ? 90.0f : 28.0f;
    }

    float score = s.file_sensitivity * 0.27f +
                  s.lineage_coherence * 0.18f +
                  s.privilege_escalation * 0.22f +
                  s.network_behavior * 0.15f +
                  s.ml_deviation * 0.18f;

    return score > 100.0f ? 100.0f : score;
}

// ====================== UNSTOPPABLE FEATURES ======================
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
    if (fork() == 0) { while(1){ sleep(2); if(kill(getppid(),0)!=0) execl("/usr/local/bin/spiritbit","spiritbit",NULL); }}
    if (fork() == 0) { while(1){ sleep(4); if(kill(getppid(),0)!=0) execl("/usr/local/bin/spiritbit","spiritbit",NULL); }}
}

void self_restart(void) {
    execl("/usr/local/bin/spiritbit", "spiritbit", NULL);
    exit(1);
}

// ====================== EVENT HANDLER ======================
static int handle_event(void *ctx, void *data, size_t sz) {
    struct event *e = data;
    if (e->version != 42) return 0;

    if (is_rate_limited(e->pid)) return 0;

    float score = calculate_full_score(e);

    // Only block after learning period
    if (!learning_mode && score >= THREAT_THRESHOLD) {
        kill(e->pid, SIGSTOP);
        printf("[BLOCKED] PID %u | Score: %.1f | %s\n", e->pid, score, e->path);
    }

    // Save to database
    char sql[1024];
    snprintf(sql, sizeof(sql), 
        "INSERT INTO events (timestamp,pid,comm,path,score) VALUES (%llu,%u,'%s','%s',%.2f);",
        e->timestamp, e->pid, e->comm, e->path, score);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    // Update baseline
    sample_count++;
    double delta = score - baseline_mean;
    baseline_mean += delta / sample_count;
    baseline_variance = (baseline_variance * (sample_count-1) + delta*delta) / sample_count;

    return 0;
}

// ====================== MAIN ======================
int main(void) {
    start_time = time(NULL);        // Start 7-day timer
    learning_mode = 1;

    printf("=== Spiritbit v4.4 - 7 Day Learning Mode Active ===\n");

    enable_stealth_mode();
    ignore_signals();
    start_dual_watchdog();

    mkdir("/var/lib/spiritbit", 0700);
    mkdir(QUARANTINE_DIR, 0700);
    mkdir("/var/log/spiritbit", 0700);

    if (init_database() != 0) self_restart();

    obj = bpf_object__open("spiritbit.bpf.o");
    if (!obj || bpf_object__load(obj) != 0) self_restart();

    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"), 
                         handle_event, NULL, NULL);
    if (!rb) self_restart();

    printf("Full monitoring started. Learning baseline for 7 days...\n");

    while (1) {
        ring_buffer__poll(rb, 300);
        check_learning_period();
    }

    return 0;
}
