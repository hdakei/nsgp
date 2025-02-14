#include <ncurses.h>
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

/* Color Pair Indices */
#define CP_HEADING   1
#define CP_MENU      2
#define CP_NORMAL    3
#define CP_CONTAINER 4
#define CP_SYSTEM    5
#define CP_HIGHLIGHT 6

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
        
        /* Read cgroup info */
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

void draw_screen(ProcessInfo *procs, int count, int filter,
                 int start, int selected, const char *search_query) {
    int height, width;
    getmaxyx(stdscr, height, width);
    
    /* Build filtered index array */
    int *filtered = malloc(count * sizeof(int));
    int filtered_count = 0;
    for (int i = 0; i < count; i++) {
        /* For now, search filter is applied on some fields */
        if (search_query == NULL || !*search_query ||
            strcasestr(procs[i].pid, search_query) ||
            strcasestr(procs[i].app_name, search_query))
            filtered[filtered_count++] = i;
    }
    
    int header_lines = 6;
    int visible = height - header_lines - 1;
    
    move(0,2);
    clrtoeol();
    attron(A_BOLD | COLOR_PAIR(CP_HEADING));
    printw("=== NS & Cgroup Viewer === (Total: %d, Filtered: %d)", count, filtered_count);
    attroff(A_BOLD | COLOR_PAIR(CP_HEADING));
    
    move(1,2);
    clrtoeol();
    attron(A_BOLD | COLOR_PAIR(CP_MENU));
    printw("Current filter: %d (Press 1=System,2=Container,3=All)", filter);
    attroff(A_BOLD | COLOR_PAIR(CP_MENU));
    
    move(2,2);
    clrtoeol();
    printw("Search query: [%s]", search_query);
    
    move(3,2);
    clrtoeol();
    attron(A_BOLD | COLOR_PAIR(CP_MENU));
    printw("[Arrows] Move  [Enter] Details  [/] Search  [c] Clear  [q] Quit  [1,2,3] Switch Filter");
    attroff(A_BOLD | COLOR_PAIR(CP_MENU));
    
    move(4,2);
    clrtoeol();
    attron(A_BOLD | COLOR_PAIR(CP_HEADING));
    printw(" %-6s %-5s %-20s %-20s %-20s %-20s",
           "PID", "Type", "Cont.Name", "Cont.Image", "AppName", "ns_net");
    attroff(A_BOLD | COLOR_PAIR(CP_HEADING));
    
    move(5,2);
    clrtoeol();
    
    for (int i = 0; i < visible; i++) {
        move(6+i,2);
        clrtoeol();
        if (i < filtered_count) {
            int idx = filtered[start + i];
            if ((start+i) == selected) {
                attron(A_BOLD | A_REVERSE | COLOR_PAIR(CP_HIGHLIGHT));
            } else {
                if (procs[idx].containerized)
                    attron(COLOR_PAIR(CP_CONTAINER));
                else
                    attron(COLOR_PAIR(CP_SYSTEM));
            }
            printw(" %-6s %-5s %-20.20s %-20.20s %-20.20s %-20.20s",
                   procs[idx].pid,
                   procs[idx].containerized ? "Cont" : "Sys",
                   procs[idx].containerized ? (procs[idx].container_name[0] ? procs[idx].container_name : "-") : "-",
                   procs[idx].containerized ? (procs[idx].container_image[0] ? procs[idx].container_image : "-") : "-",
                   procs[idx].app_name,
                   procs[idx].ns_net);
            if ((start+i) == selected) {
                attroff(A_BOLD | A_REVERSE | COLOR_PAIR(CP_HIGHLIGHT));
            } else {
                if (procs[idx].containerized)
                    attroff(COLOR_PAIR(CP_CONTAINER));
                else
                    attroff(COLOR_PAIR(CP_SYSTEM));
            }
        }
    }
    free(filtered);
    refresh();
}

int main(void) {
    printf("======================================\n");
    printf(" Welcome to the NS & Cgroup Viewer!   \n");
    printf("======================================\n\n");
    printf("Initially, choose what you want to see:\n");
    printf(" 1) Only system (non-container) processes\n");
    printf(" 2) Only containerized (Docker, LXC, etc.) processes\n");
    printf(" 3) All processes on the system\n\n");
    printf("Your choice (1,2,3): ");
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input.\n");
        return EXIT_FAILURE;
    }
    if (choice < 1 || choice > 3) {
        fprintf(stderr, "Invalid selection.\n");
        return EXIT_FAILURE;
    }
    
    int filter = choice;
    int procCount = 0;
    ProcessInfo *procs = gather_process_info(filter, &procCount);
    if (!procs) {
        fprintf(stderr, "Failed to gather process information.\n");
        return EXIT_FAILURE;
    }
    
    initscr();
    noecho();
    cbreak();
    keypad(stdscr, TRUE);
    
    if (has_colors()) {
        start_color();
        init_pair(CP_HEADING,   COLOR_WHITE,  COLOR_BLUE);
        init_pair(CP_MENU,      COLOR_BLACK,  COLOR_YELLOW);
        init_pair(CP_NORMAL,    COLOR_WHITE,  COLOR_BLACK);
        init_pair(CP_CONTAINER, COLOR_YELLOW, COLOR_BLACK);
        init_pair(CP_SYSTEM,    COLOR_GREEN,  COLOR_BLACK);
        init_pair(CP_HIGHLIGHT, COLOR_WHITE,  COLOR_RED);
    }
    
    int ch;
    int start = 0;
    int selected = 0;
    char search_query[256] = "";
    search_query[0] = '\0';
    
    while (1) {
        draw_screen(procs, procCount, filter, start, selected, search_query);
        ch = getch();
        if (ch == 'q' || ch == 'Q') {
            break;
        } else if (ch == '/') {
            echo();
            curs_set(1);
            int height, width;
            getmaxyx(stdscr, height, width);
            move(height - 1, 0);
            clrtoeol();
            printw("Enter new search text: ");
            char buf[256] = {0};
            getnstr(buf, sizeof(buf) - 1);
            noecho();
            curs_set(0);
            strcpy(search_query, buf);
            selected = 0;
            start = 0;
        } else if (ch == 'c' || ch == 'C') {
            search_query[0] = '\0';
            selected = 0;
            start = 0;
        } else if (ch == '1' || ch == '2' || ch == '3') {
            filter = ch - '0';
            free(procs);
            procs = gather_process_info(filter, &procCount);
            search_query[0] = '\0';
            selected = 0;
            start = 0;
        } else if (ch == KEY_UP) {
            if (selected > 0) selected--;
            if (selected < start) start = selected;
        } else if (ch == KEY_DOWN) {
            int local_count = 0;
            for (int i = 0; i < procCount; i++) {
                if ( (search_query[0] == '\0') || strcasestr(procs[i].pid, search_query) || strcasestr(procs[i].app_name, search_query) )
                    local_count++;
            }
            if (selected < local_count - 1) selected++;
            int height, width;
            getmaxyx(stdscr, height, width);
            int visible = height - 6 - 1;
            if (selected >= start + visible) {
                start = selected - visible + 1;
            }
        } else if (ch == KEY_PPAGE) {
            int height, width;
            getmaxyx(stdscr, height, width);
            int visible = height - 6 - 1;
            selected -= visible;
            if (selected < 0) selected = 0;
            if (selected < start) start = selected;
        } else if (ch == KEY_NPAGE) {
            int local_count = 0;
            for (int i = 0; i < procCount; i++) {
                if ((search_query[0] == '\0') || strcasestr(procs[i].pid, search_query) || strcasestr(procs[i].app_name, search_query))
                    local_count++;
            }
            int height, width;
            getmaxyx(stdscr, height, width);
            int visible = height - 6 - 1;
            selected += visible;
            if (selected >= local_count) selected = local_count - 1;
            if (selected >= start + visible) {
                start = selected - visible + 1;
            }
        } else if (ch == '\n' || ch == KEY_ENTER) {
            int local_count = 0;
            int chosen_idx = -1;
            for (int i = 0; i < procCount; i++) {
                if ((search_query[0] == '\0') || strcasestr(procs[i].pid, search_query) || strcasestr(procs[i].app_name, search_query)) {
                    if (local_count == selected) {
                        chosen_idx = i;
                        break;
                    }
                    local_count++;
                }
            }
            if (chosen_idx >= 0) {
                /* Detailed view will be implemented in the next commit */
                // For now, simply display a placeholder.
                move(0,0);
                clrtoeol();
                printw("Detailed view not implemented in this commit. Press any key...");
                refresh();
                getch();
            }
        }
    }
    
    endwin();
    free(procs);
    return EXIT_SUCCESS;
}
