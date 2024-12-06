from flask import Flask, request, jsonify
import ctypes
import os
import time

app = Flask(__name__)


@app.route('/analyst', methods=['POST'])
def run_in_sandbox():
    if 'file' not in request.files:
        return jsonify({'status': 'Bad request', 'message': 'File or command must be not null!', 'data': None}), 400
    file = request.files['file']
    command = request.form['command']

    directory = './file/'
    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = directory + file.filename
    file.save(file_path)
    command = get_command(file_path)
    print('Command ----> '+command + '\n')

    sandbox = ctypes.CDLL('./sandbox.so')
    sandbox.run.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char_p))

    args = [b"./sandbox", command.encode()]
    arg_array = (ctypes.c_char_p * len(args))(*args)

    sandbox.run(len(args), arg_array)

    result = "Execution completed"
    print('Done!')
    return jsonify({'status': 'success', 'aiDetech': result, 'ptraceOutput': 'tesst', 'errors': ['a', 'b', 'c']})


def get_command(file_path):
    """
    Trả về lệnh command phù hợp để thực thi file dựa trên loại file.
    """
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".py":
        # Python script
        command = f"python3 {file_path}"
    elif ext == ".c":
        # Compile and execute C program
        output_executable = file_path.replace(".c", "")
        command = f"gcc {
            file_path} -o {output_executable} && ./{output_executable}"
    elif ext == ".sh":
        # Shell script
        command = f"bash {file_path}"
    elif ext == ".java":
        # Compile and execute Java program
        class_name = os.path.splitext(os.path.basename(file_path))[0]
        command = f"javac {file_path} && java {class_name}"
    elif ext in [".txt", ".md"]:
        # Text file (read-only)
        command = f"cat {file_path}"
    else:
        raise ValueError(f"Unsupported file type: {ext}")

    return command


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
