// spiritbitwatchdog.c - Spiritbit v4.4 Dual-Layer Self-Healing Watchdog
// Purpose: Ensure the main daemon is unkillable and always running

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>

#define MAIN_DAEMON_PATH    "/usr/local/bin/spiritbit"
#define RESTART_DELAY       3
#define MAX_RESTARTS        9999

int main(void) {
    int restart_count = 0;
    pid_t main_pid;

    printf("=== Spiritbit v4.4 Watchdog Started ===\n");
    printf("Monitoring main daemon for crashes or kills...\n");

    // Make watchdog more resilient
    prctl(PR_SET_NAME, "spiritbit-wd", 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    while (restart_count < MAX_RESTARTS) {
        main_pid = fork();

        if (main_pid == 0) {
            // ==================== CHILD PROCESS (Main Daemon) ====================
            execl(MAIN_DAEMON_PATH, "spiritbit", NULL);
            
            // If we reach here, exec failed
            fprintf(stderr, "[WATCHDOG] Failed to start spiritbit daemon\n");
            exit(1);
        } 
        else if (main_pid > 0) {
            // ==================== PARENT PROCESS (Watchdog) ====================
            printf("[WATCHDOG] Started main daemon with PID: %d\n", main_pid);

            int status;
            waitpid(main_pid, &status, 0);

            // Main daemon died or was killed
            if (WIFEXITED(status)) {
                printf("[WATCHDOG] Main daemon exited with code: %d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("[WATCHDOG] Main daemon killed by signal: %d\n", WTERMSIG(status));
            } else {
                printf("[WATCHDOG] Main daemon terminated abnormally\n");
            }

            restart_count++;
            printf("[WATCHDOG] Restarting main daemon... (Attempt %d/%d)\n", 
                   restart_count, MAX_RESTARTS);
            
            sleep(RESTART_DELAY);
        } 
        else {
            // Fork failed
            fprintf(stderr, "[WATCHDOG] Fork failed! Retrying in 5 seconds...\n");
            sleep(5);
        }
    }

    fprintf(stderr, "[WATCHDOG] Maximum restart attempts reached. Exiting.\n");
    return 1;
}
