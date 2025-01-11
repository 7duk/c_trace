from flask import Flask, request, jsonify
import ctypes
import os
import time
from run_docker import SandboxRunner
from lstm_model import SyscallAnalyzer

app = Flask(__name__)


@app.route('/analyst', methods=['POST'])
def run_in_sandbox():
    if 'file' not in request.files:
        return jsonify({'status': 'Bad request', 'message': 'File or command must be not null!', 'data': None}), 400
    file = request.files['file']
    # command = request.form['command']

    directory = './file/'
    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = directory + file.filename
    file.save(file_path)
    file_local = os.path.abspath(file_path.strip())
    runner = SandboxRunner()
    syscalls, log_file = runner.run(1, file_local)
    logs = runner.logs(log_file)
    analyst = SyscallAnalyzer()
    predict = analyst.predict_file(syscalls)
    return jsonify({'status': 'success', 'predict': predict, 'ptraceOutput': logs})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
