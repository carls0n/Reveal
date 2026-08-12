#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_MODULES 512
#define MODULE_NAME_LEN 64
#define MAX_DISCOVERIES 128

char visible_modules[MAX_MODULES][MODULE_NAME_LEN];
int visible_count = 0;

// Structure to buffer discovery events until both phases finish execution
typedef struct {
    int type; // 1 = Phase 1 Revealed (Scenario A), 2 = Phase 1 Toggled Off (Scenario B), 3 = Phase 2 Sysfs
    int sig;
    char name[MODULE_NAME_LEN];
} Discovery;

Discovery discoveries[MAX_DISCOVERIES];
int total_discoveries = 0;

// Populates a tracking array from /proc/modules (Used by both scanning methods)
int get_module_list(char list[MAX_MODULES][MODULE_NAME_LEN]) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
         
    char line[512]; 
    int count = 0;
         
    while (fgets(line, sizeof(line), f) && count < MAX_MODULES) {
        char *space = strchr(line, ' ');
        if (space) {
            size_t len = space - line;
            if (len >= MODULE_NAME_LEN) len = MODULE_NAME_LEN - 1;
                         
            strncpy(list[count], line, len);
            list[count][len] = '\0';
            count++;
        }
    }
         
    fclose(f);
    return count;
}

// Helper to determine if /sys/module/<name>/initstate exists
bool has_initstate(const char *mod_name) {
    char path[512]; 
    struct stat st;
         
    snprintf(path, sizeof(path), "/sys/module/%s/initstate", mod_name);
    return (stat(path, &st) == 0);
}

// Method 1: Tries to provoke rootkit toggles via POSIX signals (1-64)
int scan_hidden_modules_via_signals(void) {
    int phase1_found = 0;

    printf("[*] Phase 1: Beginning isolated 1-64 signal scan for hidden LKMs...\n");

    for (int sig = 1; sig <= 64; sig++) {
        if (sig == 9 || sig == 19 || sig == 32 || sig == 33) {
            continue;
        }

        char before_list[MAX_MODULES][MODULE_NAME_LEN];
        char after_list[MAX_MODULES][MODULE_NAME_LEN];

        int before_count = get_module_list(before_list);

        pid_t pid = fork();
        if (pid < 0) {
            perror("[-] Fork failed during signal scan");
            return 0;
        }

        if (pid == 0) {
            setsid();
            syscall(SYS_kill, 0, sig);
            exit(EXIT_SUCCESS);
        } else {
            int status;
            waitpid(pid, &status, 0);
            usleep(100000); // Allow time for rootkit state transitions

            int after_count = get_module_list(after_list);
            int found_lkm = 0;

            // Scenario A: Rootkit was fully hidden and popped into /proc/modules
            for (int i = 0; i < after_count; i++) {
                int match = 0;
                for (int j = 0; j < before_count; j++) {
                    if (strcmp(after_list[i], before_list[j]) == 0) {
                        match = 1;
                        break;
                    }
                }
                if (!match) {
                    if (total_discoveries < MAX_DISCOVERIES) {
                        discoveries[total_discoveries].type = 1;
                        discoveries[total_discoveries].sig = sig;
                        strncpy(discoveries[total_discoveries].name, after_list[i], MODULE_NAME_LEN - 1);
                        discoveries[total_discoveries].name[MODULE_NAME_LEN - 1] = '\0';
                        total_discoveries++;
                    }
                    found_lkm = 1;
                    phase1_found++;
                    break;
                }
            }

            // Scenario B: Rootkit was already visible but dropped out of /proc/modules
            if (!found_lkm) {
                for (int i = 0; i < before_count; i++) {
                    int match = 0;
                    for (int j = 0; j < after_count; j++) {
                        if (strcmp(before_list[i], after_list[j]) == 0) {
                            match = 1;
                            break;
                        }
                    }
                    if (!match) {
                        if (total_discoveries < MAX_DISCOVERIES) {
                            discoveries[total_discoveries].type = 2;
                            discoveries[total_discoveries].sig = sig;
                            strncpy(discoveries[total_discoveries].name, before_list[i], MODULE_NAME_LEN - 1);
                            discoveries[total_discoveries].name[MODULE_NAME_LEN - 1] = '\0';
                            total_discoveries++;
                        }
                        found_lkm = 1;
                        phase1_found++;
                                                 
                        pid_t reset_pid = fork();
                        if (reset_pid == 0) {
                            setsid();
                            syscall(SYS_kill, 0, sig);
                            exit(EXIT_SUCCESS);
                        } else {
                            waitpid(reset_pid, &status, 0);
                        }
                        break;
                    }
                }
            }
        }

        // Halt Phase 1 loop early if an entry is caught
        if (phase1_found > 0) {
            break;
        }
    }

    return phase1_found;
}

// Method 2: Fallback scan checking sysfs structures directly against procfs
int scan_sysfs_discrepancies(void) {
    DIR *dir = opendir("/sys/module");
    if (!dir) {
        perror("[-] Failed to open /sys/module");
        return 0;
    }

    struct dirent *entry;
    int sysfs_found = 0;
    printf("[*] Phase 2: Beginning SYSFS cross-reference tracking...\n");
    sleep(2);
    visible_count = get_module_list(visible_modules);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (!has_initstate(entry->d_name)) {
            continue;
        }

        bool found = false;
        for (int i = 0; i < visible_count; i++) {
            if (strcmp(entry->d_name, visible_modules[i]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            if (total_discoveries < MAX_DISCOVERIES) {
                discoveries[total_discoveries].type = 3;
                discoveries[total_discoveries].sig = 0;
                strncpy(discoveries[total_discoveries].name, entry->d_name, MODULE_NAME_LEN - 1);
                discoveries[total_discoveries].name[MODULE_NAME_LEN - 1] = '\0';
                total_discoveries++;
            }
            sysfs_found++;
        }
    }
    closedir(dir);
    return sysfs_found;
}

int main(int argc, char *argv[]) {
    bool run_phase1 = true;
    bool run_phase2 = true;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--skip-phase1") == 0) {
            run_phase1 = false;
        } else if (strcmp(argv[i], "--skip-phase2") == 0) {
            run_phase2 = false;
        } else {
            fprintf(stderr, "Usage: %s [--skip-phase1] [--skip-phase2]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "[*] Error: This utility must be executed with root (sudo) privileges.\n");
        return EXIT_FAILURE;
    }

    int signal_discoveries = 0;
    int sysfs_discoveries = 0;

    if (run_phase1) {
        signal_discoveries = scan_hidden_modules_via_signals();
    }
    if (run_phase2) {
        sysfs_discoveries = scan_sysfs_discrepancies();
    }
         
    // Track specific Phase 1 scenario results for the final message strings
    bool scenario_a_happened = false;
    bool scenario_b_happened = false;

    // Unified output summary block
    for (int i = 0; i < total_discoveries; i++) {
        if (discoveries[i].type == 1) {
            scenario_a_happened = true;
            printf("[*] Hidden Rootkit Revealed Via Signal %d:\n", discoveries[i].sig);
            printf("[*] Target Identity: %s\n", discoveries[i].name);
            printf("[*] Remediation: sudo rmmod %s\n", discoveries[i].name);
        } else if (discoveries[i].type == 2) {
            scenario_b_happened = true;
            printf("[*] Rootkit Detected (Toggled Off Via Signal %d):\n", discoveries[i].sig);
            printf("[*] Target Identity: %s\n", discoveries[i].name);
            printf("[*] Remediation: sudo rmmod %s\n", discoveries[i].name);
        } else if (discoveries[i].type == 3) {
            printf("[*] Hidden LKM Rootkit Detected Via SYSFS Analysis:\n");
            printf("[*] Target Identity: %s\n", discoveries[i].name);
           // printf("[*] Vector Analysis: Dynamically allocated but completely missing from /proc/modules.\n");
            printf("[*] Remediation: Reboot and run this scan again.\n");
        }
    }

    if (total_discoveries == 0) {
        printf("[*] Scan complete. No rootkits were found.\n");
    }

    return EXIT_SUCCESS;
}
