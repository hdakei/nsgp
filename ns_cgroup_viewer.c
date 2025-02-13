#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#define BUFFER_SIZE 1024

/* Minimal process structure */
typedef struct {
    char pid[16];
    char app_name[256];
    // More fields will be added later.
} ProcessInfo;

/* Check if a string is numeric */
int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char)*str)) return 0;
        str++;
    }
    return 1;
}

/* Scan /proc and gather basic process info */
ProcessInfo *gather_process_info(int *count_out) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return NULL;
    }
    int capacity = 256;
    ProcessInfo *processes = malloc(capacity * sizeof(ProcessInfo));
    if (!processes) {
        perror("malloc");
        closedir(proc_dir);
        return NULL;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!is_numeric(entry->d_name)) continue;
        
        char proc_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%s", entry->d_name);

        ProcessInfo pi;
        memset(&pi, 0, sizeof(pi));
        strncpy(pi.pid, entry->d_name, sizeof(pi.pid) - 1);
        
        char comm_path[PATH_MAX];
        snprintf(comm_path, sizeof(comm_path), "%s/comm", proc_path);
        FILE *fp = fopen(comm_path, "r");
        if (fp) {
            if (fgets(pi.app_name, sizeof(pi.app_name), fp)) {
                pi.app_name[strcspn(pi.app_name, "\n")] = '\0';
            }
            fclose(fp);
        } else {
            strcpy(pi.app_name, "-");
        }
        
        if (count >= capacity) {
            capacity *= 2;
            ProcessInfo *tmp = realloc(processes, capacity * sizeof(ProcessInfo));
            if (!tmp) {
                perror("realloc");
                free(processes);
                closedir(proc_dir);
                return NULL;
            }
            processes = tmp;
        }
        processes[count++] = pi;
    }
    closedir(proc_dir);
    *count_out = count;
    return processes;
}

int main(void) {
    int procCount = 0;
    ProcessInfo *procs = gather_process_info(&procCount);
    if (!procs) {
        fprintf(stderr, "Failed to gather process information.\n");
        return EXIT_FAILURE;
    }
    
    printf("Found %d processes.\n", procCount);
    for (int i = 0; i < procCount; i++) {
        printf("PID: %s, Name: %s\n", procs[i].pid, procs[i].app_name);
    }
    
    free(procs);
    return EXIT_SUCCESS;
}
