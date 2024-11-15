from flask import Flask, request, jsonify
import ctypes
import os

# # Load thư viện chia sẻ C
# sandbox = ctypes.CDLL('./sandbox.so')

# sandbox.run.argtypes = (ctypes.c_int,ctypes.POINTER(ctypes.c_char_p))
# # Prepare the argument list
# args = [b"./sandbox", b"./test"]  # Thay đổi "/bin/ls" thành đường dẫn chương trình bạn muốn chạy
# arg_array = (ctypes.c_char_p * len(args))(*args)
# sandbox.run(len(args),arg_array)


app = Flask(__name__)
@app.route('/analyst', methods=['POST'])
def run_in_sandbox():
   
    # Lấy file từ request
    print('hello world!---->1')
    file = request.files['file']
    print('hello world!---->2')
    command = request.form['command']  # Lấy command từ form data
    print('hello world!')
    # Lưu file vào thư mục hiện tại
    file_path = './' + file.filename
    file.save(file_path)

    # Gọi thư viện C và chạy hàm run
    sandbox = ctypes.CDLL('./sandbox.so')
    sandbox.run.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char_p))

    # Tạo danh sách các đối số, bao gồm command và file path
    args = [b"./sandbox", command.encode()]
    arg_array = (ctypes.c_char_p * len(args))(*args)
    
    # Thực thi
    sandbox.run(len(args), arg_array)

    # Sau khi thực thi, có thể xử lý kết quả (nếu có)
    result = "Execution completed"  # Cập nhật với kết quả thực tế

    return jsonify({'status': 'success', 'result': result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
