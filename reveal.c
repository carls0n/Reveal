#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#define max_modules 512
#define name_size 256

int get_module_list(char list[max_modules][name_size]) {
    DIR *d = opendir("/sys/module");
    if (!d) return 0;
    
    struct dirent *dir;
    int count = 0;
    while ((dir = readdir(d)) != NULL && count < max_modules) {
        if (dir->d_name[0] != '.') { 
            strncpy(list[count], dir->d_name, name_size - 1);
            list[count][name_size - 1] = '\0';
            count++;
        }
    }
    closedir(d);
    return count;
}

int main() {
    printf("[*] Starting isolated 1-64 signal scan for hidden LKMs...\n");

    for (int sig = 1; sig <= 64; sig++) {
        // Skip uncatchable global and internal glibc thread synchronization signals
        if (sig == 9 || sig == 19 || sig == 32 || sig == 33) {
            continue;
        }

        char before_list[max_modules][name_size];
        char after_list[max_modules][name_size];

        int before_count = get_module_list(before_list);

        pid_t pid = fork();
        if (pid < 0) {
            perror("Fork failed");
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            setsid(); 
            syscall(SYS_kill, 0, sig);
            exit(EXIT_SUCCESS);
        } else {
            int status;
            waitpid(pid, &status, 0);

            usleep(100000); 

            int after_count = get_module_list(after_list);
            int found_lkm = 0;

            // Scenario A: Module was hidden and newly unhidden (Appeared)
            for (int i = 0; i < after_count; i++) {
                int match = 0;
                for (int j = 0; j < before_count; j++) {
                    if (strcmp(after_list[i], before_list[j]) == 0) {
                        match = 1;
                        break;
                    }
                }
                if (!match) {
                    printf("\n[!] ALERT: Hidden module revealed itself!\n");
                    printf("[+] Detected Module: %s\n", after_list[i]);
                    printf("[+] Actions to take - sudo rmmod -f %s\n", after_list[i]);
                    found_lkm = 1;
                }
            }

            // Scenario B: Module was already visible but was toggled OFF (Disappeared)
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
                        printf("\n[!] ALERT: Visible module found!\n");
                        printf("[+] Detected Module: %s\n", before_list[i]);
                        printf("[+] Actions to take - sudo rmmod -f %s\n", before_list[i]);
                        found_lkm = 1;
                        
                        pid_t reset_pid = fork();
                        if (reset_pid == 0) {
                            setsid();
                            syscall(SYS_kill, 0, sig);
                            exit(EXIT_SUCCESS);
                        } else {
                            waitpid(reset_pid, &status, 0);
                        }
                    }
                }
            }

        }
    }

    printf("\n[*] Scan complete. Hidden entries are now permanently exposed.\n");
    return EXIT_SUCCESS;
}

