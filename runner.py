import ctypes
import sys

def run_sandbox(input_path, output_path):
    # Load thư viện C
    sandbox = ctypes.CDLL('./sandbox.so')
    sandbox.run.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char_p))

    # Tạo danh sách đối số
    args = [b"./sandbox", input_path.encode()]
    arg_array = (ctypes.c_char_p * len(args))(*args)

    # Gọi sandbox
    sandbox.run(len(args), arg_array)

    # Lưu kết quả
    with open(output_path, "w") as f:
        f.write("Execution completed successfully.\n")

if __name__ == "__main__":
    # Đọc file input
    input_file = "/input_file"
    output_file = "/output/result.txt"

    try:
        run_sandbox(input_file, output_file)
    except Exception as e:
        with open(output_file, "w") as f:
            f.write(f"Error during execution: {str(e)}\n")
