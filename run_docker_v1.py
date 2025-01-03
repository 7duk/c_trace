import docker
import re
import tarfile
import os
import io
from runner import SandboxExecutor

container_id =  ""
def run_docker_container(test_file_path, client,container_test_path):
    try:
        # Chạy container với bind mount và truyền tham số
        container = client.containers.run(
            image="runner_container",             # Tên image đã build
            command=[container_test_path],        # Tham số truyền vào cho CMD
            volumes={test_file_path: {'bind': container_test_path, 'mode': 'ro'}},  # Bind file test vào container
            # remove=True,                          # Xóa container sau khi chạy xong
            detach=True                          # Chạy đồng bộ và chờ kết quả
        )
        container_id = container.id
        # Lấy log đầu ra
        result = container.wait()
        print(f"Container exited with status: {result['StatusCode']}")
        logs = container.logs()
        return logs
    except docker.errors.DockerException as e:
        print(f"Error: {e}")
        return None

def extract_syscalls(file_path):
    syscalls = ""
    
    with open(file_path, 'r') as file:
        for line in file:
            # Kiểm tra nếu dòng có chứa 'Syscalls :'
            match = re.search(r'Syscalls\s*:\s*\[(.*?)\]', line)
            if match:
                # Lấy các giá trị Syscalls dưới dạng chuỗi
                syscalls_str = match.group(1)
                syscalls = f"{syscalls_str}"
                break  # Giả sử Syscalls chỉ xuất hiện một lần, nếu có nhiều lần, bỏ dòng này
    
    return syscalls







def copy_file_from_container(container_id, container_file_path, host_output_path):
    try:
        client = docker.from_env()
        
        # Kết nối với container
        container = client.containers.get(container_id)
        
        # Lấy file từ container dưới dạng tar archive
        bits, stat = container.get_archive(container_file_path)
        
        # Tạo thư mục đích nếu chưa tồn tại
        os.makedirs(os.path.dirname(host_output_path), exist_ok=True)
        
        # Giải nén tar archive và lưu vào host
        with open(host_output_path, "wb") as f:
            for chunk in bits:
                f.write(chunk)
        
        # Giải nén file tar để lấy file cụ thể
        with tarfile.open(host_output_path) as tar:
            tar.extractall(path=os.path.dirname(host_output_path))
        
        print(f"File copied to: {host_output_path}")
    except docker.errors.DockerException as e:
        print(f"Error: {e}")

def run(case, file_predict):
    syscalls = ""
    # Khởi tạo Docker client
    client = docker.from_env()
    # run virtualbox
    if case == 1:
        executor = SandboxExecutor(library_path='./sandbox.so', program_name='./sandbox')
        result = executor.run(file_predict);
        cleaned_path = os.path.abspath(result)
        str = extract_syscalls(cleaned_path)
        syscalls = str
    # run docker
    elif case == 2:
        syscalls = "1"
    return syscalls



syscalls = run(1,"./test")
print("Syscall ---> "+ syscalls)
# # Dừng container
# container.stop()
# container.remove()

# Đường dẫn file 'test' trên máy host

# test_file_path = "/file/safe/decuong.docx"  # Thay bằng đường dẫn đầy đủ của file test trên máy host
# remote_file_log="/app"
# # Chạy container và lấy kết quả
# output = run_docker_container(test_file_path)
# if output:
#     print(f"Output: {output.decode().strip()}")
#     for line in output.decode().splitlines():
#         if "Return value:" in line:
#             part = line.split("Return value:")[-1]
#             log_path_index = part.find("/log")
#             if log_path_index != -1:
#                 clean_line = part[log_path_index:]
#                 remote_file_log += clean_line
#                 print("Test ---> "+remote_file_log)

# Đường dẫn tới file log của bạn
# file_path = 'test_20241219_090412.log' 
# syscalls = extract_syscalls(file_path)

# # In ra giá trị Syscalls dưới dạng chuỗi
# print("Extracted Syscalls:", syscalls)