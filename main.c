#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void analyze_syscall(pid_t child_pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    long syscall = regs.orig_rax;

    // Kiểm tra các system call đáng ngờ
    switch(syscall) {
        case SYS_open:
        case SYS_read:
        case SYS_write: {
            char filename[256];
            long long addr = regs.rdi;
            int i = 0;
            long data;
            while (i < 256) {
                data = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
                memcpy(filename + i, &data, sizeof(long));
                if (memchr(&data, 0, sizeof(long)))
                    break;
                i += sizeof(long);
            }
            filename[255] = '\0';
            printf("Suspicious system call: %ld, File: %s\n", syscall, filename);
            break;
        }
        case SYS_execve:
            printf("Suspicious system call: execve (possible code execution)\n");
            break;
        case SYS_clone:
        case SYS_fork:
        case SYS_vfork:
            printf("Suspicious system call: process creation\n");
            break;
        case SYS_connect:
            printf("Suspicious system call: network connection\n");
            break;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], argv + 1);
    } else {
        int status;
        while (1) {
            wait(&status);
            if (WIFEXITED(status))
                break;
            analyze_syscall(child_pid);
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        }
    }
    return 0;
}