import ctypes
import sys

class SandboxExecutor:
    def __init__(self, library_path: str, program_name: str):
        # Load thư viện C khi tạo đối tượng SandboxExecutor
        self.sandbox = ctypes.CDLL(library_path)
        self.program_name = program_name
        # Định nghĩa kiểu đối số và kiểu trả về cho hàm `run` trong thư viện
        self.sandbox.run.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char_p))
        self.sandbox.run.restype = ctypes.c_char_p

    def run(self, input_path: str) -> str:
        """
        Chạy chương trình sandbox với đường dẫn đầu vào.
        Trả về kết quả thực thi dưới dạng chuỗi.
        """
        # Tạo danh sách đối số và chuẩn bị mảng
        args = [self.program_name.encode(), input_path.encode()]
        arg_array = (ctypes.c_char_p * len(args))(*args)
        # Gọi hàm `run` từ thư viện C và trả về kết quả
        return self.sandbox.run(len(args), arg_array).decode("utf-8")

if __name__ == "__main__":
    # Kiểm tra tham số đầu vào
    if len(sys.argv) != 2:
        print("Usage: python3 file.py <input_path>")
        sys.exit(1)

    # Đọc đường dẫn input từ tham số dòng lệnh
    input_file = sys.argv[1]
    
    # Khởi tạo đối tượng SandboxExecutor
    executor = SandboxExecutor(library_path='./sandbox.so', program_name='./sandbox')

    # Gọi hàm `run` để thực thi sandbox
    try:
        result = executor.run(input_file)
        print(f"Return value: {result}")
    except Exception as e:
        print(f"Error during execution: {str(e)}")
