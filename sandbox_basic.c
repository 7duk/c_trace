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

#define MAX_SYSCALLS 100
#define PATH_MAX 4096
#define LOG_FILE "sandbox.log"

// Danh sách các system call được phép
int allowed_syscalls[] = {
    SYS_open,       // 2
    SYS_read,       // 0
    SYS_write,      // 1
    SYS_close,      // 3
    SYS_exit,       // 60
    SYS_exit_group, // 231
    SYS_execve,     // 59
    SYS_fork,       // 57
    SYS_brk,        // 12
    SYS_mmap,       // 9
    // SYS_access, //21
    SYS_openat,          // 257
    SYS_pread64,         // 17
    SYS_fstat,           // 5
    SYS_arch_prctl,      // 158
    SYS_set_tid_address, // 218
    SYS_set_robust_list, // 273
    SYS_rseq,            // 334
    SYS_mprotect,        // 10
    SYS_prlimit64,       // 302
    SYS_munmap,          // 11
    SYS_getrandom,       // 318
    SYS_stat,            // Lấy thông tin file
    SYS_statfs,          // Lấy thông tin hệ thống file
    SYS_readlink,        // Đọc liên kết symlink
};
int num_allowed_syscalls = sizeof(allowed_syscalls) / sizeof(int);

const char *interpreters[][2] = {
    {".py", "python3"},
    {".js", "node"},
    {".jar", "java -jar"},
    {".sh", "bash"},
    {".pdf", "evince"},
    {".docx", "libreoffice"},
    {".xlsx", "libreoffice"},
    {".csv", "libreoffice"}
};

const int num_interpreters = sizeof(interpreters) / sizeof(interpreters[0]);

enum LogLevel
{
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
};

struct ResourceUsage
{
    long cpu_time;
    long memory_usage;
    long io_operations;
};

void get_source_info(unsigned long long rip, const char *binary)
{
    printf("Rip info : %llx\n", rip);
    printf("Binary : %s\n", binary);
    char command[PATH_MAX * 2];
    snprintf(command, sizeof(command), "addr2line -e '%s' %llx", binary, rip);
    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen");
        return;
    }
    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("Source info: %s", output);
    }
    pclose(fp);
}

void get_executable_path(pid_t pid, char *buffer, size_t size)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, buffer, size - 1);
    if (len != -1)
    {
        buffer[len] = '\0';
        printf("Executable path: %s\n", buffer);
    }
    else
    {
        fprintf(stderr, "Failed to get executable path. Error: %s\n", strerror(errno));
        strncpy(buffer, "unknown", size - 1);
        buffer[size - 1] = '\0';
    }
}

char *determine_interpreter(const char *filename)
{
    magic_t magic_cookie;
    const char *mime_type;
    char *interpreter = NULL;

    // Khởi tạo magic library
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL)
    {
        log_message(LOG_ERROR, "Failed to initialize magic library");
        return NULL;
    }

    // Load magic database
    if (magic_load(magic_cookie, NULL) != 0)
    {
        log_message(LOG_ERROR, "Failed to load magic library");
        magic_close(magic_cookie);
        return NULL;
    }

    // Lấy MIME type của file
    mime_type = magic_file(magic_cookie, filename);
    if (mime_type == NULL)
    {
        log_message(LOG_ERROR, "Failed to determine file type");
        magic_close(magic_cookie);
        return NULL;
    }

    // Kiểm tra phần mở rộng file
    char *ext = strrchr(filename, '.');
    if (ext)
    {
        for (int i = 0; i < num_interpreters; i++)
        {
            if (strcmp(ext, interpreters[i][0]) == 0)
            {
                interpreter = strdup(interpreters[i][1]);
                break;
            }
        }
    }

    // Nếu không tìm thấy interpreter từ phần mở rộng, thử theo MIME type
    if (interpreter == NULL)
    {
        if (strstr(mime_type, "python"))
        {
            interpreter = strdup("python3");
        }
        else if (strstr(mime_type, "javascript"))
        {
            interpreter = strdup("node");
        }
        else if (strstr(mime_type, "x-java-archive"))
        {
            interpreter = strdup("java -jar");
        }
    }

    magic_close(magic_cookie);
    return interpreter;
}

int is_syscall_allowed(long syscall)
{
    for (int i = 0; i < num_allowed_syscalls; i++)
    {
        if (syscall == allowed_syscalls[i])
        {
            return 1;
        }
    }
    return 0;
}

// New function for logging
void log_message(enum LogLevel level, const char *format, ...)
{
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
        perror("Failed to open log file");
        return;
    }

    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; // Remove newline

    fprintf(log_file, "[%s] ", date);

    switch (level)
    {
    case LOG_INFO:
        fprintf(log_file, "[INFO] ");
        break;
    case LOG_WARNING:
        fprintf(log_file, "[WARNING] ");
        break;
    case LOG_ERROR:
        fprintf(log_file, "[ERROR] ");
        break;
    }

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}

void monitor_resources(pid_t pid, struct ResourceUsage *usage)
{
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == 0)
    {
        usage->cpu_time = ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
                          ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
        usage->memory_usage = ru.ru_maxrss;
        usage->io_operations = ru.ru_inblock + ru.ru_oublock;
        log_message(LOG_INFO, "Resource usage - CPU time: %ld us, Memory: %ld KB, I/O: %ld operations",
                    usage->cpu_time, usage->memory_usage, usage->io_operations);
    }
}

void set_resource_limits()
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 5; // 5 seconds CPU time
    if (setrlimit(RLIMIT_CPU, &rl) == -1)
    {
        perror("setrlimit CPU");
    }
    rl.rlim_cur = rl.rlim_max = 50 * 1024 * 1024; // 50MB of memory
    if (setrlimit(RLIMIT_AS, &rl) == -1)
    {
        perror("setrlimit AS");
    }
}

void run_sandbox(pid_t child, pid_t parent_pid)
{
    int status;
    struct user_regs_struct regs;
    int in_syscall = 0;
    struct ResourceUsage usage;

    while (1)
    {
        if (waitpid(child, &status, 0) == -1)
        {
            perror("waitpid");
            log_message(LOG_ERROR, "waitpid failed: %s", strerror(errno));
            break;
        }

        if (WIFEXITED(status))
        {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
            log_message(LOG_INFO, "Child exited with status %d", WEXITSTATUS(status));
            break;
        }
        else if (WIFSIGNALED(status))
        {
            printf("Child killed by signal %d\n", WTERMSIG(status));
            log_message(LOG_INFO, "Child killed by signal %d", WTERMSIG(status));
            break;
        }
        else if (WIFSTOPPED(status))
        {
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1)
            {
                perror("ptrace GETREGS");
                log_message(LOG_ERROR, "ptrace GETREGS failed: %s", strerror(errno));
                continue;
            }

            if (in_syscall == 0)
            {
                printf("Syscall number: %lld\n", regs.orig_rax);
                log_message(LOG_INFO, "Syscall number: %lld", regs.orig_rax);
                if (!is_syscall_allowed(regs.orig_rax) && child != parent_pid)
                {
                    printf("Blocked syscall: %lld\n", regs.orig_rax);
                    printf("Position: %lld\n", regs.rip);
                    log_message(LOG_WARNING, "Blocked syscall: %lld at position: %lld", regs.orig_rax, regs.rip);

                    char executable[PATH_MAX];
                    get_executable_path(child, executable, sizeof(executable));
                    get_source_info(regs.rip, executable);

                    regs.rax = -EPERM;
                    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1)
                    {
                        perror("ptrace SETREGS");
                        log_message(LOG_ERROR, "ptrace SETREGS failed: %s", strerror(errno));
                    }
                }
                in_syscall = 1;
            }
            else
            {
                printf("Syscall return value: %lld\n", regs.rax);
                log_message(LOG_INFO, "Syscall return value: %lld", regs.rax);
                in_syscall = 0;
            }
            monitor_resources(child, &usage);
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1)
            {
                perror("ptrace SYSCALL");
                log_message(LOG_ERROR, "ptrace SYSCALL failed: %s", strerror(errno));
                break;
            }
        }
    }
}

void run(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <program to run in sandbox>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Xác định trình thông dịch
    char *interpreter = determine_interpreter(argv[1]);

    log_message(LOG_INFO, "Starting sandbox for program: %s", argv[1]);
    pid_t parent_pid = getpid();
    pid_t child = fork();

    if (child == 0)
    {
        // Child process
        printf("Child process created!\n");
        log_message(LOG_INFO, "Child process created");
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("ptrace TRACEME");
            log_message(LOG_ERROR, "ptrace TRACEME failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        set_resource_limits();
        // if (execv(argv[1], &argv[1]) == -1)
        // {
        //     log_message(LOG_ERROR, "execv failed: %s", strerror(errno));
        //     perror("execv");
        //     exit(EXIT_FAILURE);
        // }
        // Nếu có trình thông dịch, sử dụng trình thông dịch
        if (interpreter)
        {
            char *args[4];
            args[0] = interpreter;
            args[1] = argv[1];
            args[2] = NULL;

            if (execvp(interpreter, args) == -1)
            {
                log_message(LOG_ERROR, "execvp failed: %s", strerror(errno));
                perror("execvp");
                free(interpreter);
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            // Nếu không có trình thông dịch, thử thực thi trực tiếp
            if (execv(argv[1], &argv[1]) == -1)
            {
                log_message(LOG_ERROR, "execv failed: %s", strerror(errno));
                perror("execv");
                exit(EXIT_FAILURE);
            }
        }
    }
    else if (child > 0)
    {
        // Parent process (sandbox)
        printf("Running '%s' in sandbox\n", argv[1]);
        log_message(LOG_INFO, "Running '%s' in sandbox", argv[1]);
        if (interpreter)
            free(interpreter);
        run_sandbox(child, parent_pid);
    }
    else
    {
        perror("fork");
        log_message(LOG_ERROR, "fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}
int main(int argc, char *argv[])
{
    run(argc, argv);
    return 0;
}
