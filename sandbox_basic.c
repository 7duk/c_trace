#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// Danh sách các system call được phép
int allowed_syscalls[] = {SYS_read, SYS_write, SYS_exit, SYS_exit_group};
int num_allowed_syscalls = sizeof(allowed_syscalls) / sizeof(int);

int is_syscall_allowed(long syscall) {
    for (int i = 0; i < num_allowed_syscalls; i++) {
        if (syscall == allowed_syscalls[i]) {
            return 1;
        }
    }
    return 0;
}

void run_sandbox(pid_t child) {
    int status;
    struct user_regs_struct regs;

    while (1) {
        wait(&status);
        if (WIFEXITED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        if (is_syscall_allowed(regs.orig_rax)) {
            printf("System call được phép: %lld\n", regs.orig_rax);
        } else {
            printf("System call bị chặn: %lld\n", regs.orig_rax);
            regs.orig_rax = -1;  // Chặn system call
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Sử dụng: %s <chương trình cần chạy trong sandbox>\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child == 0) {
        // Tiến trình con
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], &argv[1]);
    } else if (child > 0) {
        // Tiến trình cha (sandbox)
        printf("Chạy '%s' trong sandbox\n", argv[1]);
        run_sandbox(child);
    } else {
        perror("fork");
        exit(1);
    }

    return 0;
}