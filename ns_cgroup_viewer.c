#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>

#define BUFFER_SIZE 1024

/* ProcessInfo structure extended with namespace fields */
typedef struct {
    char pid[16];
    char app_name[256];
    char ns_net[128];
    char ns_uts[128];
    char ns_ipc[128];
    char ns_pid[128];
    char ns_user[128];
    char ns_mnt[128];
    char ns_cgroup[128];
    char ns_time[128];
} ProcessInfo;

/* Check if a string is numeric */
int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char)*str))
            return 0;
        str++;
    }
    return 1;
}

/* Safe snprintf helper */
int safe_snprintf(char *dest, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(dest, size, fmt, ap);
    va_end(ap);
    if (ret < 0) return -1;
    if ((size_t)ret >= size) return -1;
    return ret;
}

/* Gather process information including namespace details */
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
        if (!is_numeric(entry->d_name))
            continue;
        char proc_path[PATH_MAX];
        if (safe_snprintf(proc_path, sizeof(proc_path), "/proc/%s", entry->d_name) < 0)
            continue;
            
        ProcessInfo pi;
        memset(&pi, 0, sizeof(pi));
        strncpy(pi.pid, entry->d_name, sizeof(pi.pid)-1);
        
        /* Read process name from /proc/[pid]/comm */
        char comm_path[PATH_MAX];
        if (safe_snprintf(comm_path, sizeof(comm_path), "%s/comm", proc_path) >= 0) {
            FILE *fp = fopen(comm_path, "r");
            if (fp) {
                if (fgets(pi.app_name, sizeof(pi.app_name), fp)) {
                    pi.app_name[strcspn(pi.app_name, "\n")] = '\0';
                }
                fclose(fp);
            } else {
                strcpy(pi.app_name, "-");
            }
        }
        
        /* Initialize namespace fields */
        strcpy(pi.ns_net, "-");
        strcpy(pi.ns_uts, "-");
        strcpy(pi.ns_ipc, "-");
        strcpy(pi.ns_pid, "-");
        strcpy(pi.ns_user, "-");
        strcpy(pi.ns_mnt, "-");
        strcpy(pi.ns_cgroup, "-");
        strcpy(pi.ns_time, "-");
        
        /* Read namespace info from /proc/[pid]/ns */
        char ns_dir_path[PATH_MAX];
        if (safe_snprintf(ns_dir_path, sizeof(ns_dir_path), "%s/ns", proc_path) >= 0) {
            DIR *ns_dir = opendir(ns_dir_path);
            if (ns_dir) {
                struct dirent *ns_ent;
                while ((ns_ent = readdir(ns_dir)) != NULL) {
                    if (!strcmp(ns_ent->d_name, ".") || !strcmp(ns_ent->d_name, ".."))
                        continue;
                    char link_path[PATH_MAX];
                    if (safe_snprintf(link_path, sizeof(link_path), "%s/%s", ns_dir_path, ns_ent->d_name) < 0)
                        continue;
                    char target[128];
                    ssize_t len = readlink(link_path, target, sizeof(target)-1);
                    if (len >= 0) {
                        target[len] = '\0';
                        if (!strcmp(ns_ent->d_name, "net"))
                            strncpy(pi.ns_net, target, sizeof(pi.ns_net)-1);
                        else if (!strcmp(ns_ent->d_name, "uts"))
                            strncpy(pi.ns_uts, target, sizeof(pi.ns_uts)-1);
                        else if (!strcmp(ns_ent->d_name, "ipc"))
                            strncpy(pi.ns_ipc, target, sizeof(pi.ns_ipc)-1);
                        else if (!strcmp(ns_ent->d_name, "pid"))
                            strncpy(pi.ns_pid, target, sizeof(pi.ns_pid)-1);
                        else if (!strcmp(ns_ent->d_name, "user"))
                            strncpy(pi.ns_user, target, sizeof(pi.ns_user)-1);
                        else if (!strcmp(ns_ent->d_name, "mnt"))
                            strncpy(pi.ns_mnt, target, sizeof(pi.ns_mnt)-1);
                        else if (!strcmp(ns_ent->d_name, "cgroup"))
                            strncpy(pi.ns_cgroup, target, sizeof(pi.ns_cgroup)-1);
                        else if (!strcmp(ns_ent->d_name, "time"))
                            strncpy(pi.ns_time, target, sizeof(pi.ns_time)-1);
                    }
                }
                closedir(ns_dir);
            }
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
        printf("PID: %s, Name: %s, ns_net: %s\n", procs[i].pid, procs[i].app_name, procs[i].ns_net);
    }
    
    free(procs);
    return EXIT_SUCCESS;
}
