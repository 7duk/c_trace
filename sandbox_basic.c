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
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>

#define PATH_MAX 4096

const char *interpreters[][2] = {
    {".py", "python3"},
    {".js", "node"},
    {".jar", "java -jar"},
    {".sh", "bash"},
    {".pdf", "evince"},
    {".doc", "libreoffice"},
    {".docx", "libreoffice"},
    {".xlsx", "libreoffice --calc"},
    {".csv", "libreoffice --calc"},
    {".exe", "wine"}};

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

static pid_t child_pid;

// Hàm xử lý khi timeout
void timeout_handler(int sig)
{
    if (child_pid > 0)
    {
        printf("Process timeout after 2 minutes. Killing process %d\n", child_pid);
        kill(child_pid, SIGKILL);
    }
}

// New function for logging
void log_message(const char *log_file, enum LogLevel level, const char *format, ...)
{
    FILE *file = fopen(log_file, "a");
    if (file == NULL)
    {
        perror("Failed to open log file");
        return;
    }

    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; // Remove newline

    fprintf(file, "[%s] ", date);

    switch (level)
    {
    case LOG_INFO:
        fprintf(file, "[INFO] ");
        break;
    case LOG_WARNING:
        fprintf(file, "[WARNING] ");
        break;
    case LOG_ERROR:
        fprintf(file, "[ERROR] ");
        break;
    }

    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    fprintf(file, "\n");
    fflush(file);
    fclose(file);
}

char *determine_interpreter(const char *filename, const char *log_file)
{
    magic_t magic_cookie;
    const char *mime_type;
    char *interpreter = NULL;

    // Khởi tạo magic library
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL)
    {
        log_message(log_file, LOG_ERROR, "Failed to initialize magic library");
        return NULL;
    }

    // Load magic database
    if (magic_load(magic_cookie, NULL) != 0)
    {
        log_message(log_file, LOG_ERROR, "Failed to load magic library");
        magic_close(magic_cookie);
        return NULL;
    }

    // Lấy MIME type của file
    mime_type = magic_file(magic_cookie, filename);
    if (mime_type == NULL)
    {
        log_message(log_file, LOG_ERROR, "Failed to determine file type");
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

int contains(const char *str, const char *substr)
{
    return strstr(str, substr) != NULL;
}

void generate_log_file_name(const char *input_file, char *log_file, size_t size)
{
    char *base = basename((char *)input_file); // Lấy tên file (không có đường dẫn)
    struct stat st;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", t);

    if (stat("./log", &st) == -1)
    {
        mkdir("./log", 0755);
    }
    if (contains(input_file, "dangerous"))
    {
        if (stat("./log/dangerous", &st) == -1)
        {
            mkdir("./log/dangerous", 0755);
        }
        snprintf(log_file, size, "./log/dangerous/%s_%s.log", base, timestamp);
    }
    else if (contains(input_file, "safe"))
    {
        if (stat("./log/safe", &st) == -1)
        {
            mkdir("./log/safe", 0755);
        }
        snprintf(log_file, size, "./log/safe/%s_%s.log", base, timestamp);
    }
    else
    {
        snprintf(log_file, size, "./log/%s_%s.log", base, timestamp); // Gắn đuôi .log vào tên file
    }
}

void monitor_resources(pid_t pid, struct ResourceUsage *usage, const char *log_file)
{
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == 0)
    {
        usage->cpu_time = ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
                          ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
        usage->memory_usage = ru.ru_maxrss;
        usage->io_operations = ru.ru_inblock + ru.ru_oublock;
        log_message(log_file, LOG_INFO, "Resource usage - CPU time: %ld us, Memory: %ld KB, I/O: %ld operations",
                    usage->cpu_time, usage->memory_usage, usage->io_operations);
    }
}

void run_sandbox(pid_t child, pid_t parent_pid, const char *filename, const char *log_file)
{
    child_pid = child; // Lưu child PID để timeout_handler có thể truy cập

    // Đặt handler cho SIGALRM
    signal(SIGALRM, timeout_handler);
    // Đặt timeout 2 phút (120 giây)
    alarm(100);

    int status;
    struct user_regs_struct regs;
    int in_syscall = 0;
    struct ResourceUsage usage;

    while (1)
    {
        if (waitpid(child, &status, 0) == -1)
        {
            perror("waitpid");
            log_message(log_file, LOG_ERROR, "waitpid failed: %s", strerror(errno));
            break;
        }

        if (WIFEXITED(status))
        {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
            log_message(log_file, LOG_INFO, "Child exited with status %d", WEXITSTATUS(status));
            break;
        }
        else if (WIFSIGNALED(status))
        {
            printf("Child killed by signal %d\n", WTERMSIG(status));
            log_message(log_file, LOG_INFO, "Child killed by signal %d", WTERMSIG(status));
            break;
        }
        else if (WIFSTOPPED(status))
        {
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1)
            {
                perror("ptrace GETREGS");
                log_message(log_file, LOG_ERROR, "ptrace GETREGS failed: %s", strerror(errno));
                continue;
            }

            if (in_syscall == 0)
            {
                printf("Syscall number: %lld\n", regs.orig_rax);
                log_message(log_file, LOG_INFO, "Syscall number: %lld", regs.orig_rax);
                in_syscall = 1;
            }
            else
            {
                printf("Syscall return value: %lld\n", regs.rax);
                log_message(log_file, LOG_INFO, "Syscall return value: %lld", regs.rax);
                in_syscall = 0;
                monitor_resources(child, &usage, log_file);
            }
            
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1)
            {
                perror("ptrace SYSCALL");
                log_message(log_file, LOG_ERROR, "ptrace SYSCALL failed: %s", strerror(errno));
                break;
            }
        }
    }
    // Hủy alarm khi process kết thúc bình thường
    alarm(0);
}

char *run(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <program to run in sandbox>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char log_file[PATH_MAX];
    generate_log_file_name(argv[1], log_file, sizeof(log_file));
    // Xác định trình thông dịch
    char *interpreter = determine_interpreter(argv[1], log_file);

    log_message(log_file, LOG_INFO, "Starting sandbox for program: %s", argv[1]);
    pid_t parent_pid = getpid();
    pid_t child = fork();

    if (child == 0)
    {
        // Child process
        printf("Child process created!\n");
        log_message(log_file, LOG_INFO, "Child process created");
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("ptrace TRACEME");
            log_message(log_file, LOG_ERROR, "ptrace TRACEME failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (interpreter)
        {
            // Tách lệnh thành các phần
            char *args[5] = {NULL};          // Tăng kích thước mảng để linh hoạt hơn
            char *cmd = strdup(interpreter); // Tạo bản sao để tránh modify chuỗi gốc

            // Biến để đếm số lượng argument
            int arg_count = 0;

            // Tách lệnh và argument
            char *token = strtok(cmd, " ");
            while (token != NULL && arg_count < 3)
            {
                args[arg_count++] = token;
                token = strtok(NULL, " ");
            }

            // Thêm đường dẫn file
            args[arg_count++] = argv[1];
            args[arg_count] = NULL; // Đảm bảo kết thúc mảng bằng NULL

            // In ra để kiểm tra (có thể loại bỏ khi không cần debug)
            printf("Executing:");
            for (int i = 0; i < arg_count; i++)
            {
                printf(" %s", args[i]);
            }
            printf("\n");

            if (execvp(args[0], args) == -1)
            {
                log_message(log_file, LOG_ERROR, "execvp failed: %s", strerror(errno));
                perror("execvp");
                free(cmd); // Giải phóng bản sao của chuỗi
                free(interpreter);
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            // Nếu không có trình thông dịch, thử thực thi trực tiếp
            char *args[] = {argv[1], NULL}; 
            if (execv(argv[1], args) == -1)
            {
                log_message(log_file, LOG_ERROR, "execv failed: %s", strerror(errno));
                perror("execv");
                exit(EXIT_FAILURE);
            }
        }
    }
    else if (child > 0)
    {
        // Parent process (sandbox)
        printf("Running '%s' in sandbox\n", argv[1]);
        log_message(log_file, LOG_INFO, "Running '%s' in sandbox", argv[1]);
        if (interpreter)
            free(interpreter);
        run_sandbox(child, parent_pid, argv[1], log_file);
    }
    else
    {
        perror("fork");
        log_message(log_file, LOG_ERROR, "fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    char *result = strdup(log_file); // Tạo bản sao động của log_file
    return result;
}
int main(int argc, char *argv[])
{
    // , "file/dangerous"
    // Mảng chứa các đường dẫn thư mục
    char *directories[] = {"file/dangerous", "file/safe"};

    // Duyệt qua từng thư mục trong mảng
    for (int dir_idx = 0; dir_idx < 2; dir_idx++)
    {
        DIR *dir = opendir(directories[dir_idx]);
        if (dir == NULL)
        {
            perror("Failed to open directory");
            return EXIT_FAILURE;
        }

        struct dirent *entry;
        // Duyệt qua từng file trong thư mục
        while ((entry = readdir(dir)) != NULL)
        {
            // Bỏ qua các thư mục '.' và '..'
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            // Tạo đường dẫn đầy đủ đến file
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", directories[dir_idx], entry->d_name);

            // In thông tin và gọi hàm run với file_path
            printf("Processing file: %s\n", file_path);

            // Cập nhật các tham số argv với đường dẫn file (ví dụ chỉ sử dụng argv[1] để truyền file vào hàm run)
            char *argv_copy[] = {argv[0], file_path}; // Lưu lại argv[0] và file_path
            run(2, argv_copy);                        //
        }

        closedir(dir); // Đóng thư mục sau khi duyệt xong
    }
    // run(argc, argv);
    return 0;
}