#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

int main()
{
    char buffer[128];
    int fd;

    // Test system call: write (this should be allowed)
    const char *message = "Kiểm tra system call write --->\n";
    write(STDOUT_FILENO, message, strlen(message)); // Sử dụng strlen để lấy chiều dài chính xác

    // Test system call: open và read (đọc nội dung từ một file)
    fd = open("testfile.txt", O_RDONLY);
    if (fd == -1)
    {
        perror("Lỗi khi mở file");
        exit(1);
    }

    // Test system call: read (this should be allowed)
    int n = read(fd, buffer, sizeof(buffer) - 1);
    if (n > 0)
    {
        buffer[n] = '\0';
        printf("Đọc được nội dung từ file: %s\n", buffer);
    }
    else
    {
        perror("Lỗi khi đọc file");
    }

    // Đóng file sau khi đọc xong
    close(fd);

    // Test system call: exit (this should be allowed)
    exit(0);

    // Nếu muốn thử system call không hợp lệ (ví dụ syscall 'fork'), thêm mã sau:
    // fork();  // System call này không nằm trong danh sách được phép
}
