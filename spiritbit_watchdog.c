#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>

#define SPIRITBIT_PATH    "/usr/bin/spiritbit"
#define MAX_RESTARTS      3
#define RESTART_WINDOW    60
#define WATCHDOG_LOG      "/var/log/spiritbit-watchdog.log"

// Log to file and stdout
void wlog(const char *msg)
{
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts)-1] = '\0'; // remove newline

    printf("[WATCHDOG] %s %s\n", ts, msg);

    FILE *f = fopen(WATCHDOG_LOG, "a");
    if (f) {
        fprintf(f, "[WATCHDOG] %s %s\n", ts, msg);
        fclose(f);
    }
}

int main()
{
    wlog("Starting Spiritbit watchdog");

    int restarts = 0;
    time_t first_restart = 0;

    while (1) {
        // Fork Spiritbit
        pid_t child = fork();

        if (child == 0) {
            // Child: become Spiritbit
            execl(SPIRITBIT_PATH, "spiritbit", NULL);
            // exec failed
            perror("execl failed");
            exit(1);
        }

        if (child < 0) {
            wlog("Fork failed, retrying in 5s");
            sleep(5);
            continue;
        }

        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Spiritbit started PID %d", child);
        wlog(msg);

        // Wait for child
        int status;
        waitpid(child, &status, 0);

        // Clean exit = user stopped it intentionally
        if (WIFEXITED(status) &&
            WEXITSTATUS(status) == 0) {
            wlog("Spiritbit clean exit. Watchdog stopping.");
            break;
        }

        // Unexpected exit
        snprintf(msg, sizeof(msg),
                 "Spiritbit died unexpectedly. Status %d",
                 WEXITSTATUS(status));
        wlog(msg);

        // Alert via syslog
        system("logger -t spiritbit-watchdog "
               "'Spiritbit died unexpectedly'");

        // Rate limit restarts
        time_t now = time(NULL);

        if (first_restart == 0) {
            first_restart = now;
            restarts = 1;
        } else if (now - first_restart < RESTART_WINDOW) {
            restarts++;
            if (restarts > MAX_RESTARTS) {
                wlog("Too many restarts. Manual intervention needed.");
                system("logger -t spiritbit-watchdog "
                       "'Spiritbit restart limit exceeded'");
                exit(1);
            }
        } else {
            // Window expired, reset
            first_restart = now;
            restarts = 1;
        }

        wlog("Restarting Spiritbit in 2 seconds");
        sleep(2);
    }

    return 0;
}
