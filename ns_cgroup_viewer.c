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
#define MAX_CGROUP_LINES 10

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
    char cgroup_lines[MAX_CGROUP_LINES][BUFFER_SIZE];
    int cgroup_line_count;
    int containerized; // 1 if containerized, else 0
    char container_id[128];
    char container_name[256];
    char container_image[256];
} ProcessInfo;

int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char)*str))
            return 0;
        str++;
    }
    return 1;
}

int safe_snprintf(char *dest, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(dest, size, fmt, ap);
    va_end(ap);
    if (ret < 0) return -1;
    if ((size_t)ret >= size) return -1;
    return ret;
}

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
        
        /* Read process name */
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
        
        /* Read namespace info */
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
        
        /* Read cgroup information */
        char cg_path[PATH_MAX];
        if (safe_snprintf(cg_path, sizeof(cg_path), "%s/cgroup", proc_path) >= 0) {
            pi.cgroup_line_count = 0;
            pi.containerized = 0;
            FILE *cgfp = fopen(cg_path, "r");
            if (cgfp) {
                char line[BUFFER_SIZE];
                while (fgets(line, sizeof(line), cgfp)) {
                    if (pi.cgroup_line_count < MAX_CGROUP_LINES) {
                        strncpy(pi.cgroup_lines[pi.cgroup_line_count], line, BUFFER_SIZE-1);
                        pi.cgroup_lines[pi.cgroup_line_count][BUFFER_SIZE-1] = '\0';
                        pi.cgroup_line_count++;
                    }
                    if (strstr(line, "docker") || strstr(line, "lxc") ||
                        strstr(line, "kubepods") || strstr(line, "container")) {
                        pi.containerized = 1;
                        char *docker_ptr = strstr(line, "docker-");
                        if (docker_ptr && !*pi.container_id) {
                            char *scope_ptr = strstr(docker_ptr, ".scope");
                            if (scope_ptr) {
                                int id_len = scope_ptr - (docker_ptr + 7);
                                if (id_len > 0 && id_len < (int)sizeof(pi.container_id)) {
                                    strncpy(pi.container_id, docker_ptr + 7, id_len);
                                    pi.container_id[id_len] = '\0';
                                }
                            }
                        }
                    }
                }
                fclose(cgfp);
            }
        }
        
        /* If containerized, run docker inspect commands */
        if (pi.containerized && pi.container_id[0]) {
            char cmd[256], buf[256];
            // Get container name.
            snprintf(cmd, sizeof(cmd), "docker inspect --format '{{.Name}}' %s 2>/dev/null", pi.container_id);
            FILE *fp = popen(cmd, "r");
            if (fp) {
                if (fgets(buf, sizeof(buf), fp)) {
                    buf[strcspn(buf, "\n")] = '\0';
                    if (buf[0] == '/')
                        memmove(buf, buf+1, strlen(buf));
                    strncpy(pi.container_name, buf, sizeof(pi.container_name)-1);
                }
                pclose(fp);
            }
            // Get container image.
            snprintf(cmd, sizeof(cmd), "docker inspect --format '{{.Config.Image}}' %s 2>/dev/null", pi.container_id);
            fp = popen(cmd, "r");
            if (fp) {
                if (fgets(buf, sizeof(buf), fp)) {
                    buf[strcspn(buf, "\n")] = '\0';
                    strncpy(pi.container_image, buf, sizeof(pi.container_image)-1);
                }
                pclose(fp);
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
        printf("PID: %s, Name: %s, Containerized: %s\n", 
               procs[i].pid, procs[i].app_name,
               procs[i].containerized ? "Yes" : "No");
        if (procs[i].containerized) {
            printf("  Container ID: %s, Name: %s, Image: %s\n", 
                   procs[i].container_id, 
                   procs[i].container_name[0] ? procs[i].container_name : "-",
                   procs[i].container_image[0] ? procs[i].container_image : "-");
        }
    }
    
    free(procs);
    return EXIT_SUCCESS;
}
