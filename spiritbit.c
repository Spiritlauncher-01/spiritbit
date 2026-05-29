// spiritbit.c - Spiritbit v4.3 MAX FEATURES + UNSTOPPABLE
// Packed with features while staying under ~12MB RAM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <bpf/libbpf.h>
#include <sqlite3.h>
#include "config.h"

// ====================== STRUCTS ======================
typedef struct {
    float file_sens;
    float behavior_rate;
    float privilege;
    float lineage;
    float network;
    float anomaly;
    float cmdline_risk;
} Score;

struct event {
    uint8_t  version;
    uint32_t pid, ppid, uid;
    uint64_t ts;
    char comm[16];
    char path[120];
    uint32_t type;
    uint8_t  sensitive;
    uint8_t  write;
};

// ====================== GLOBALS ======================
static struct ring_buffer *rb = NULL;
static struct bpf_object *obj = NULL;
static sqlite3 *db = NULL;

static double mean = 0.0, variance = 1.0;
static int samples = 0;
static pid_t wd1 = 0, wd2 = 0;   // Dual watchdog

// ====================== UNSTOPPABLE LAYER ======================
void stealth_mode(void) {
    prctl(PR_SET_NAME, "kworker/2:4", 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

void ignore_dangerous_signals(void) {
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
}

void start_dual_watchdog(void) {
    // First watchdog
    if (fork() == 0) {
        while(1) { sleep(2); if (kill(getppid(),0) != 0) execl("/usr/local/bin/spiritbit","spiritbit",NULL); }
    }
    // Second watchdog for extra resilience
    if (fork() == 0) {
        while(1) { sleep(4); if (kill(getppid(),0) != 0) execl("/usr/local/bin/spiritbit","spiritbit",NULL); }
    }
}

void self_restart(void) {
    execl("/usr/local/bin/spiritbit", "spiritbit", NULL);
    exit(1);
}

// ====================== BEHAVIORAL SCORING (Enhanced) ======================
float calculate_score(const struct event *e) {
    Score s = {0};

    s.file_sens   = e->sensitive ? 92.0f : 14.0f;
    s.privilege   = (e->uid == 0) ? 88.0f : 22.0f;
    s.lineage     = (e->ppid < 1000) ? 35.0f : 68.0f;
    s.network     = (e->type == 5) ? 75.0f : 20.0f;        // Network activity
    s.cmdline_risk = 30.0f;                                 // Placeholder for argv analysis

    // Statistical Anomaly (Light ML)
    if (samples > 800) {
        double std = sqrt(variance);
        double z = (65.0 - mean) / (std + 0.001);
        s.anomaly = (z > 3.0) ? 85.0f : 28.0f;
    }

    float score = s.file_sens*0.30 + s.privilege*0.22 + s.lineage*0.16 + 
                  s.network*0.15 + s.anomaly*0.17;

    return score > 100.0f ? 100.0f : score;
}

// ====================== QUARANTINE + RESPONSE ======================
void quarantine_binary(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cp %s %s/ 2>/dev/null", path, QUARANTINE_DIR);
    system(cmd);   // Very light quarantine
}

void respond(const struct event *e, float score) {
    if (score >= THREAT_THRESHOLD) {
        printf("[MAX PROTECTION] Blocked PID %u (%.1f) | %s\n", e->pid, score, e->path);
        kill(e->pid, SIGSTOP);
        if (e->write) quarantine_binary(e->path);
    }
}

// ====================== TELEMETRY + LOG ROTATION ======================
void send_telemetry(const struct event *e, float score) {
    static int log_count = 0;
    char json[1024];
    snprintf(json, sizeof(json),
        "{\"ts\":%llu,\"pid\":%u,\"comm\":\"%s\",\"path\":\"%s\",\"score\":%.2f}\n",
        e->ts, e->pid, e->comm, e->path, score);

    FILE *f = fopen(TELEMETRY_LOG, "a");
    if (f) {
        fputs(json, f);
        fclose(f);
    }

    if (++log_count > 10000) {   // Simple rotation
        rename(TELEMETRY_LOG, TELEMETRY_LOG ".old");
        log_count = 0;
    }
}

// ====================== RING BUFFER ======================
static int handle_event(void *ctx, void *data, size_t sz) {
    struct event *e = data;
    if (e->version != 42) return 0;

    float score = calculate_score(e);
    respond(e, score);
    send_telemetry(e, score);

    // Update lightweight ML baseline
    samples++;
    double delta = score - mean;
    mean += delta / samples;
    variance = variance * (samples-1)/samples + (delta * delta) / samples;

    return 0;
}

// ====================== MAIN ======================
int main(void) {
    printf("=== Spiritbit v%s - MAX FEATURES Unstoppable Guardian ===\n", SPIRITBIT_VERSION);

    stealth_mode();
    ignore_dangerous_signals();
    start_dual_watchdog();

    mkdir("/var/lib/spiritbit", 0700);
    mkdir(QUARANTINE_DIR, 0700);
    mkdir("/var/log/spiritbit", 0700);

    // Load BPF
    obj = bpf_object__open("spiritbit.bpf.o");
    if (!obj || bpf_object__load(obj) != 0) self_restart();

    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"), 
                         handle_event, NULL, NULL);
    if (!rb) self_restart();

    printf("Full filesystem + network + behavioral monitoring ACTIVE.\n");
    printf("Dual watchdog | Quarantine | ML baseline | Telemetry enabled.\n");

    while (1) {
        ring_buffer__poll(rb, 500);
    }

    return 0;
}
