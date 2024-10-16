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
};
int num_allowed_syscalls = sizeof(allowed_syscalls) / sizeof(int);

#define PATH_MAX 4096

// Hàm ánh xạ địa chỉ đến dòng mã nguồn
void get_source_info(unsigned long long rip, const char *binary)
{
    char command[512];
    // Sử dụng dấu ngoặc kép xung quanh đường dẫn của file thực thi để xử lý khoảng trắng
    snprintf(command, sizeof(command), "addr2line -e %s %llx", binary, rip);
    system(command);
}

// Hàm lấy tên file thực thi của tiến trình
void get_executable_path(pid_t pid, char *buffer, size_t size)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, buffer, size - 1); // Giảm 1 để giữ chỗ cho null terminator
    if (len != -1)
    {
        buffer[len] = '\0'; // Đảm bảo chuỗi kết thúc
        printf("Đường dẫn của file thực thi: %s\n", buffer);
    }
    else
    {
        // perror("readlink");
        printf("Không thể lấy đường dẫn của file thực thi. Lỗi: %s\n", strerror(errno));
        strncpy(buffer, "unknown", size); // Nếu có lỗi, gán giá trị mặc định
    }
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

void run_sandbox(pid_t child)
{
    int status;
    struct user_regs_struct regs;
    int in_syscall = 0; // 0: trước khi thực hiện syscall, 1: sau syscall

    while (1)
    {
        wait(&status); // Chờ tiến trình con dừng lại
        if (WIFEXITED(status))
        { // Tiến trình con kết thúc
            break;
        }

        if (WIFSTOPPED(status))
        {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (in_syscall == 0)
            { // Trước khi thực hiện syscall
                printf("System call số: %lld\n", regs.orig_rax);
                if (!is_syscall_allowed(regs.orig_rax))
                {
                    printf("Bị chặn: %lld\n", regs.orig_rax);

                    printf("Position: %lld\n", regs.rip);

                    char executable[PATH_MAX];
                    get_executable_path(child, executable, sizeof(executable));

                    // Ánh xạ địa chỉ RIP đến dòng mã nguồn
                    get_source_info(regs.rip, executable);
                    // regs.orig_rax = -1;  // Chặn system call
                    // ptrace(PTRACE_SETREGS, child, NULL, &regs);
                    ptrace(PTRACE_KILL, child, NULL, NULL);
                    break;
                }

                in_syscall = 1; // Đánh dấu đang sau khi syscall
            }
            else
            {
                in_syscall = 0; // Sau khi syscall
            }

            ptrace(PTRACE_SYSCALL, child, NULL, NULL); // Tiếp tục theo dõi syscall
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Sử dụng: %s <chương trình cần chạy trong sandbox>\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child == 0)
    {
        // Tiến trình con
        printf("Đã tạo tiến trình con!\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // Yêu cầu giám sát bởi cha
        if (execv(argv[1], &argv[1]) == -1)
        {
            printf("Execv failed: %s\n", strerror(errno));
        }
    }
    else if (child > 0)
    {
        // Tiến trình cha (sandbox)
        printf("Chạy '%s' trong sandbox\n", argv[1]);
        run_sandbox(child); // Bắt đầu giám sát tiến trình con
    }
    else
    {
        perror("fork");
        exit(1);
    }

    return 0;
}
