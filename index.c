#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h> // Sử dụng thư viện EVP cho SHA-1
#include <ctype.h>
#include <sys/syscall.h>

#define MAX_FILENAME_LENGTH 256
#define HASH_LENGTH EVP_MD_size(EVP_sha1()) // Độ dài hash SHA1

// File cần theo dõi
const char *monitored_file = "example.pdf"; // Thay đổi đường dẫn file theo nhu cầu

// Hash của các file độc hại đã biết (chỉ là ví dụ)
const char *malicious_hashes[] = {
    "dummy_hash_value_1",
    "dummy_hash_value_2",
    // Thêm các hash khác ở đây
};

// Hàm tính toán hash SHA-1 của file
void compute_file_hash(const char *filename, unsigned char *hash_output) {
    FILE *file = fopen(filename, "rb");
    if (file) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Khởi tạo ngữ cảnh hash
        EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL); // Khởi động SHA-1

        unsigned char buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            EVP_DigestUpdate(mdctx, buffer, bytes_read); // Cập nhật với dữ liệu đọc được
        }
        EVP_DigestFinal_ex(mdctx, hash_output, NULL); // Kết thúc và lấy hash
        EVP_MD_CTX_free(mdctx); // Giải phóng ngữ cảnh
        fclose(file);
    } else {
        perror("fopen");
    }
}

// Hàm chuyển đổi hash sang chuỗi hexa
void hash_to_hex(const unsigned char *hash, char *hex_output) {
    for (int i = 0; i < HASH_LENGTH; i++) {
        sprintf(hex_output + (i * 2), "%02x", hash[i]);
    }
}

// Hàm kiểm tra file có mã độc hay không
int is_malicious_file(const char *filename) {
    unsigned char hash[HASH_LENGTH];
    char hex_output[HASH_LENGTH * 2 + 1]; // Mảng để lưu trữ hash dạng chuỗi

    compute_file_hash(filename, hash);
    hash_to_hex(hash, hex_output);
    hex_output[HASH_LENGTH * 2] = '\0'; // Kết thúc chuỗi

    // Kiểm tra hash với danh sách các file độc hại
    for (size_t i = 0; i < sizeof(malicious_hashes) / sizeof(malicious_hashes[0]); i++) {
        if (strcmp(hex_output, malicious_hashes[i]) == 0) {
            return 1; // File độc hại
        }
    }
    return 0; // File an toàn
}

// Hàm để đọc thông tin CPU và RAM
void print_resource_usage(pid_t pid) {
    char path[40];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *stat_file = fopen(path, "r");
    if (stat_file) {
        int utime, stime;
        fscanf(stat_file, "%*d %*s %*s %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d %d", &utime, &stime);
        fclose(stat_file);
        
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE *status_file = fopen(path, "r");
        if (status_file) {
            char line[256];
            while (fgets(line, sizeof(line), status_file)) {
                if (strncmp(line, "VmSize:", 7) == 0) {
                    printf("Memory Usage: %s", line);
                }
            }
            fclose(status_file);
        }

        // Hiển thị thông tin CPU
        printf("CPU Time: User time = %d, System time = %d\n", utime, stime);
    } else {
        perror("fopen");
    }
}

void analyze_syscall(pid_t child_pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    long syscall = regs.orig_rax;

    switch (syscall) {
        case SYS_open:
        case SYS_read:
        case SYS_write: {
            char filename[MAX_FILENAME_LENGTH];
            long addr = regs.rdi;  // Lấy địa chỉ của filename
            int i = 0;
            long data;

            // Đọc filename từ không gian địa chỉ của tiến trình con
            while (i < MAX_FILENAME_LENGTH - 1) {
                data = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
                if (data == -1 && errno != 0) {
                    perror("ptrace PEEKDATA");
                    break;
                }
                memcpy(filename + i, &data, sizeof(long));
                if (memchr(&data, 0, sizeof(long))) break; // Dừng khi gặp ký tự null
                i += sizeof(long);
            }
            filename[MAX_FILENAME_LENGTH - 1] = '\0'; // Đảm bảo kết thúc chuỗi

            // Kiểm tra xem file được mở có phải là file cần theo dõi không
            if (strcmp(filename, monitored_file) == 0) {
                printf("Monitored file accessed: %s, System call: %ld\n", filename, syscall);

                // Kiểm tra mã độc
                if (is_malicious_file(filename)) {
                    printf("Warning: Malicious file detected: %s\n", filename);
                }

                // Theo dõi hiệu suất
                print_resource_usage(child_pid);
            }
            break;
        }
        // Có thể thêm các system call khác ở đây
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Tiến trình con
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], argv + 1);
        perror("execvp"); // In ra lỗi nếu execvp thất bại
        exit(EXIT_FAILURE);
    } else {
        // Tiến trình cha
        int status;
        while (1) {
            wait(&status);
            if (WIFEXITED(status))
                break; // Tiến trình con đã thoát

            analyze_syscall(child_pid); // Phân tích system call
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); // Tiếp tục theo dõi
        }
    }
    return 0;
}
