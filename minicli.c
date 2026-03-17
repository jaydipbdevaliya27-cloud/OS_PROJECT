#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <direct.h> 
#include <tlhelp32.h> // Required for Process Management (tasks/kill)

// --- ANSI COLOR CODES ---
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RED     "\033[31m"

#define MAX_INPUT 1024
#define MAX_HISTORY 10

// --- GLOBALS FOR HISTORY ---
char cmd_history[MAX_HISTORY][MAX_INPUT];
int history_count = 0;

// ==========================================
// 1. UI & HELP MENU
// ==========================================
// void print_banner() {
//     printf(COLOR_CYAN COLOR_BOLD);
//     printf("\n==================================================\n");
//     printf("||         isVerified() SECURE SHELL            ||\n");
//     printf("||         Pure C Execution Engine Active       ||\n");
//     printf("==================================================\n" COLOR_RESET);
//     printf("Type 'help' to see available commands.\n\n");
// }

void print_help() {
    printf(COLOR_CYAN "Available Commands & Features:\n" COLOR_RESET);
    printf(COLOR_YELLOW "  help" COLOR_RESET "         - Show this menu\n");
    printf(COLOR_YELLOW "  clear / cls" COLOR_RESET "  - Clear the terminal screen\n");
    printf(COLOR_YELLOW "  cd <dir>" COLOR_RESET "     - Change directory\n");
    printf(COLOR_YELLOW "  time / date" COLOR_RESET "  - Show current system time\n");
    printf(COLOR_YELLOW "  add a b" COLOR_RESET "      - Calculator: Add two numbers\n");
    printf(COLOR_YELLOW "  history" COLOR_RESET "      - Show the last 10 commands executed\n");
    
    printf(COLOR_CYAN   "\nAdvanced OS Features:\n" COLOR_RESET);
    printf(COLOR_YELLOW "  sysinfo" COLOR_RESET "      - Show live RAM and system load\n");
    printf(COLOR_YELLOW "  tasks / ps" COLOR_RESET "   - List all active system processes (PCBs)\n");
    printf(COLOR_YELLOW "  kill <PID>" COLOR_RESET "   - Forcefully terminate a process by ID\n");
    printf(COLOR_YELLOW "  read <file>" COLOR_RESET "  - Read file contents via C streams (cat equivalent)\n");
    printf(COLOR_YELLOW "  lock" COLOR_RESET "         - Trigger environment security lockdown\n");
    
    printf(COLOR_CYAN   "\nLinux Native Translations:\n" COLOR_RESET);
    printf(COLOR_YELLOW "  ls, grep, rm, rmdir, pwd, echo" COLOR_RESET " (All supported!)\n");
    printf(COLOR_YELLOW "  exit" COLOR_RESET "         - Close the shell\n\n");
}

// ==========================================
// 2. CORE OS FEATURES
// ==========================================

void log_command(char *raw_cmd) {
    FILE *file = fopen(".audit_log.txt", "a"); 
    if (file == NULL) return; 
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(file, "[%d-%02d-%02d %02d:%02d:%02d] EXEC: %s\n", 
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
            tm.tm_hour, tm.tm_min, tm.tm_sec, raw_cmd);
    fclose(file);
}

void add_to_history(char *cmd) {
    if (history_count < MAX_HISTORY) {
        strcpy(cmd_history[history_count], cmd);
        history_count++;
    } else {
        for (int i = 1; i < MAX_HISTORY; i++) {
            strcpy(cmd_history[i - 1], cmd_history[i]);
        }
        strcpy(cmd_history[MAX_HISTORY - 1], cmd);
    }
}

void show_history() {
    printf(COLOR_CYAN "\n--- Command History ---\n" COLOR_RESET);
    for (int i = 0; i < history_count; i++) {
        printf(COLOR_YELLOW " %2d " COLOR_RESET " %s\n", i + 1, cmd_history[i]);
    }
    printf("\n");
}

void show_sysinfo() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    printf(COLOR_CYAN "\n--- Live System Resource Monitor ---\n" COLOR_RESET);
    printf("Total RAM: %llu MB\n", memInfo.ullTotalPhys / (1024 * 1024));
    printf("Used RAM:  %llu MB\n", (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024 * 1024));
    if (memInfo.dwMemoryLoad > 80) {
        printf("Load Status: " COLOR_RED "%lu%% (HEAVY LOAD)\n" COLOR_RESET, memInfo.dwMemoryLoad);
    } else {
        printf("Load Status: " COLOR_GREEN "%lu%% (NORMAL)\n" COLOR_RESET, memInfo.dwMemoryLoad);
    }
    printf("\n");
}

void show_tasks() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }
    printf(COLOR_CYAN "\n--- Active System Processes ---\n" COLOR_RESET);
    printf("%-10s | %s\n", "PID", "Executable Name");
    printf("------------------------------------------\n");
    do {
        printf(COLOR_YELLOW "%-10lu" COLOR_RESET " | %s\n", pe32.th32ProcessID, pe32.szExeFile);
    } while (Process32Next(hProcessSnap, &pe32));
    printf("\n");
    CloseHandle(hProcessSnap);
}

void kill_process(char *pid_str) {
    if (pid_str == NULL) {
        printf(COLOR_RED "Usage: kill <PID>\n" COLOR_RESET);
        return;
    }
    DWORD pid = (DWORD)atoi(pid_str);
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        printf(COLOR_RED "Error: Could not access process %lu.\n" COLOR_RESET, pid);
        return;
    }
    if (TerminateProcess(hProcess, 0)) {
        printf(COLOR_GREEN "Successfully terminated process %lu.\n" COLOR_RESET, pid);
    } else {
        printf(COLOR_RED "Failed to terminate process %lu.\n" COLOR_RESET, pid);
    }
    CloseHandle(hProcess);
}

void read_file(char *filename) {
    if (filename == NULL) {
        printf(COLOR_RED "Usage: read <filename>\n" COLOR_RESET);
        return;
    }
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf(COLOR_RED "Error: Could not open file.\n" COLOR_RESET);
        return;
    }
    char line[512]; 
    int line_num = 1;
    printf(COLOR_CYAN "\n--- Reading: %s ---\n" COLOR_RESET, filename);
    while (fgets(line, sizeof(line), file)) {
        printf(COLOR_YELLOW "%3d | " COLOR_RESET "%s", line_num++, line);
    }
    printf("\n");
    fclose(file);
}

void show_time() {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("System Time: %02d:%02d:%02d\n", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void calc_add(char *a_str, char *b_str) {
    if (a_str == NULL || b_str == NULL) {
        printf(COLOR_RED "Usage: add <num1> <num2>\n" COLOR_RESET);
        return;
    }
    printf("Result: %.2f\n", atof(a_str) + atof(b_str));
}

// ==========================================
// 3. WINDOWS EXECUTION ENGINE
// ==========================================
int execute_os_command(char *raw_input) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char command_line[MAX_INPUT + 20];
    snprintf(command_line, sizeof(command_line), "cmd.exe /c \"%s\"", raw_input);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf(COLOR_RED "Failed to execute command.\n" COLOR_RESET);
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exit_code == 0) ? 0 : 1;
}

// ==========================================
// 4. MAIN REPL LOOP
// ==========================================
int main() {
    char input[MAX_INPUT];
    char raw_input[MAX_INPUT]; 
    char cwd[MAX_INPUT];       
    int is_locked = 0; 

    // print_banner();

    while (1) {
        if (is_locked) {
            printf(COLOR_BOLD COLOR_RED "[LOCKED] > " COLOR_RESET);
        } else if (_getcwd(cwd, sizeof(cwd)) != NULL) {
            printf(COLOR_BOLD COLOR_GREEN "[MiniCLI %s] > " COLOR_RESET, cwd);
        } else {
            printf(COLOR_BOLD COLOR_GREEN "[MiniCLI] > " COLOR_RESET);
        }

        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = 0; 
        if (strlen(input) == 0) continue;

        strcpy(raw_input, input);
        log_command(raw_input);
        add_to_history(raw_input);

        char *cmd = strtok(input, " \t");
        char *arg1 = strtok(NULL, " \t");
        char *arg2 = strtok(NULL, " \t");

        if (is_locked) {
            if (strcmp(cmd, "unlock") == 0 && arg1 != NULL && strcmp(arg1, "1234") == 0) {
                is_locked = 0; 
                printf(COLOR_GREEN "Security override accepted. Environment unlocked.\n" COLOR_RESET);
            } else {
                printf(COLOR_RED "ENVIRONMENT LOCKED. Type 'unlock 1234' to proceed.\n" COLOR_RESET);
            }
            continue; 
        }

        if (strcmp(cmd, "exit") == 0) {
            printf(COLOR_YELLOW "Shutting down MiniCLI...\n" COLOR_RESET);
            break;
        } 
        else if (strcmp(cmd, "help") == 0) print_help();
        else if (strcmp(cmd, "sysinfo") == 0) show_sysinfo();
        else if (strcmp(cmd, "history") == 0) show_history();
        else if (strcmp(cmd, "tasks") == 0 || strcmp(cmd, "ps") == 0) show_tasks();
        else if (strcmp(cmd, "kill") == 0) kill_process(arg1);
        else if (strcmp(cmd, "lock") == 0) {
            is_locked = 1;
            system("cls"); 
            printf(COLOR_RED "ENVIRONMENT LOCKED.\n" COLOR_RESET);
        }
        else if (strcmp(cmd, "read") == 0 || strcmp(cmd, "cat") == 0) read_file(arg1);
        else if (strcmp(cmd, "clear") == 0 || strcmp(cmd, "cls") == 0) system("cls"); 
        else if (strcmp(cmd, "time") == 0 || strcmp(cmd, "date") == 0) show_time();
        else if (strcmp(cmd, "add") == 0) calc_add(arg1, arg2);
        else if (strcmp(cmd, "cd") == 0) {
            if (arg1 == NULL) printf(COLOR_RED "Usage: cd <directory>\n" COLOR_RESET);
            else if (_chdir(arg1) != 0) printf(COLOR_RED "Directory not found.\n" COLOR_RESET);
        } 
        else if (strcmp(cmd, "ls") == 0) {
            char win_cmd[MAX_INPUT];
            snprintf(win_cmd, sizeof(win_cmd), "dir %s", raw_input + 2);
            execute_os_command(win_cmd);
        }
        else if (strcmp(cmd, "grep") == 0) {
            char win_cmd[MAX_INPUT];
            snprintf(win_cmd, sizeof(win_cmd), "findstr %s", raw_input + 4);
            execute_os_command(win_cmd);
        }
        else if (strcmp(cmd, "rm") == 0) {
            char win_cmd[MAX_INPUT];
            snprintf(win_cmd, sizeof(win_cmd), "del %s", raw_input + 2);
            execute_os_command(win_cmd);
        }
        else if (strcmp(cmd, "rmdir") == 0 || strcmp(cmd, "echo") == 0) execute_os_command(raw_input);
        else if (strcmp(cmd, "pwd") == 0) execute_os_command("cd");
        else execute_os_command(raw_input);
    }
    return 0;
}