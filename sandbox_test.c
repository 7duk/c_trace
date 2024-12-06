#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <stdarg.h>
#include <magic.h>
#include <limits.h>

#define MAX_SYSCALLS 100
#define PATH_MAX 4096
#define LOG_FILE "sandbox.log"

// Danh sách các system call được phép
int allowed_syscalls[] = {
    SYS_open, SYS_read, SYS_write, SYS_close, SYS_exit, SYS_exit_group,
    SYS_execve, SYS_fork, SYS_brk, SYS_mmap, SYS_openat, SYS_pread64,
    SYS_fstat, SYS_arch_prctl, SYS_set_tid_address, SYS_set_robust_list,
    SYS_rseq, SYS_mprotect, SYS_prlimit64, SYS_munmap, SYS_getrandom,
    SYS_stat, SYS_statfs, SYS_readlink};
int num_allowed_syscalls = sizeof(allowed_syscalls) / sizeof(int);

// Danh sách trình thông dịch
const char *interpreters[][2] = {
    {".py", "python3"}, {".js", "node"}, {".jar", "java -jar"},
    {".sh", "bash"}, {".pdf", "evince"}, {".docx", "libreoffice"},
    {".xlsx", "libreoffice"}, {".csv", "libreoffice"}};
const int num_interpreters = sizeof(interpreters) / sizeof(interpreters[0]);

enum LogLevel {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
};

struct ResourceUsage {
    long cpu_time;
    long memory_usage;
    long io_operations;
};

// Hàm ghi log
void log_message(enum LogLevel level, const char *format, ...) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; // Loại bỏ ký tự xuống dòng

    fprintf(log_file, "[%s] ", date);

    switch (level) {
        case LOG_INFO: fprintf(log_file, "[INFO] "); break;
        case LOG_WARNING: fprintf(log_file, "[WARNING] "); break;
        case LOG_ERROR: fprintf(log_file, "[ERROR] "); break;
    }

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}

// Hàm kiểm tra lệnh gọi hệ thống có được phép không
int is_syscall_allowed(long syscall) {
    for (int i = 0; i < num_allowed_syscalls; i++) {
        if (syscall == allowed_syscalls[i]) {
            return 1;
        }
    }
    return 0;
}

// Hàm xác định trình thông dịch phù hợp
char *determine_interpreter(const char *filename) {
    magic_t magic_cookie;
    const char *mime_type;
    char *interpreter = NULL;

    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        log_message(LOG_ERROR, "Failed to initialize magic library");
        return NULL;
    }

    if (magic_load(magic_cookie, NULL) != 0) {
        log_message(LOG_ERROR, "Failed to load magic library");
        magic_close(magic_cookie);
        return NULL;
    }

    mime_type = magic_file(magic_cookie, filename);
    if (mime_type == NULL) {
        log_message(LOG_ERROR, "Failed to determine file type");
        magic_close(magic_cookie);
        return NULL;
    }

    char *ext = strrchr(filename, '.');
    if (ext) {
        for (int i = 0; i < num_interpreters; i++) {
            if (strcmp(ext, interpreters[i][0]) == 0) {
                interpreter = strdup(interpreters[i][1]);
                break;
            }
        }
    }

    if (interpreter == NULL) {
        if (strstr(mime_type, "pdf")) interpreter = strdup("evince");
        else if (strstr(mime_type, "word")) interpreter = strdup("libreoffice");
        else if (strstr(mime_type, "excel")) interpreter = strdup("libreoffice");
    }

    magic_close(magic_cookie);
    return interpreter;
}

// Đặt giới hạn tài nguyên
void set_resource_limits() {
    struct rlimit rl;

    rl.rlim_cur = rl.rlim_max = 5; // 5 giây CPU
    if (setrlimit(RLIMIT_CPU, &rl) == -1) perror("setrlimit CPU");

    rl.rlim_cur = rl.rlim_max = 50 * 1024 * 1024; // 50MB bộ nhớ
    if (setrlimit(RLIMIT_AS, &rl) == -1) perror("setrlimit AS");
}

// Chạy chương trình trong sandbox
void run_sandbox(pid_t child) {
    int status;
    struct user_regs_struct regs;
    int in_syscall = 0;

    while (1) {
        if (waitpid(child, &status, 0) == -1) {
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }

        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                continue;
            }

            if (in_syscall == 0) {
                if (!is_syscall_allowed(regs.orig_rax)) {
                    log_message(LOG_WARNING, "Blocked syscall: %lld", regs.orig_rax);
                    regs.rax = -EPERM; // Trả về lỗi
                    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
                        perror("ptrace SETREGS");
                    }
                }
                in_syscall = 1;
            } else {
                in_syscall = 0;
            }

            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
                perror("ptrace SYSCALL");
                break;
            }
        }
    }
}

// Hàm chính
void run(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program to run>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *interpreter = determine_interpreter(argv[1]);

    pid_t child = fork();
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
            exit(EXIT_FAILURE);
        }
        set_resource_limits();
        if (interpreter) {
            execlp(interpreter, interpreter, argv[1], NULL);
        } else {
            execv(argv[1], &argv[1]);
        }
        perror("execv");
        exit(EXIT_FAILURE);
    } else if (child > 0) {
        run_sandbox(child);
    } else {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (interpreter) free(interpreter);
}

int main(int argc, char *argv[]) {
    run(argc, argv);
    return 0;
}
