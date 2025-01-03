import docker
import re
import tarfile
import os
from runner import SandboxExecutor

class SandboxRunner:
    def __init__(self):
        self.client = docker.from_env()
        self.container_id = ""

    def run_docker_container(self, image_name, test_file_path, container_test_path):
        try:
            container = self.client.containers.run(
                image=image_name,
                command=[container_test_path],
                volumes={test_file_path: {'bind': container_test_path, 'mode': 'ro'}},
                detach=True
            )
            self.container_id = container.id
            result = container.wait()
            print(f"Container exited with status: {result['StatusCode']}")
            logs = container.logs()
            return logs
        except docker.errors.DockerException as e:
            print(f"Error: {e}")
            return None

    def extract_syscalls(self, file_path):
        syscalls = ""
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    match = re.search(r'Syscalls\s*:\s*\[(.*?)\]', line)
                    if match:
                        syscalls = match.group(1)
                        break
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error reading file: {e}")
        return syscalls

    def copy_file_from_container(self, container_id, container_file_path, host_output_path):
        try:
            container = self.client.containers.get(container_id)
            bits, stat = container.get_archive(container_file_path)
            os.makedirs(os.path.dirname(host_output_path), exist_ok=True)
            with open(host_output_path, "wb") as f:
                for chunk in bits:
                    f.write(chunk)
            with tarfile.open(host_output_path) as tar:
                tar.extractall(path=os.path.dirname(host_output_path))
            print(f"File copied to: {host_output_path}")
        except docker.errors.DockerException as e:
            print(f"Error: {e}")

    def run(self, case, file_predict):
        syscalls = ""
        log_file = ""
        if case == 1:
            executor = SandboxExecutor(library_path='./sandbox.so', program_name='./sandbox')
            result = executor.run(file_predict)
            cleaned_path = os.path.abspath(result.strip())
            log_file = cleaned_path
            syscalls = self.extract_syscalls(cleaned_path)
        elif case == 2:
            # Docker execution logic can be implemented here.
            syscalls = "Docker execution not implemented."
        return syscalls,log_file
    
    def logs(self,file_predict):
        log = []
        try:
            with open(file_predict, 'r') as file:
                for line in file:
                    match = re.search(r'Syscalls\s*:\s*\[(.*?)\]', line)
                    if not match:
                       log.append(line)
        except FileNotFoundError:
            print(f"File not found: {file_predict}")
        except Exception as e:
            print(f"Error reading file: {e}")
        return log

if __name__ == "__main__":
    runner = SandboxRunner()
    syscalls = runner.run(1, "/file/safe/data.csv")
    print("Syscall ---> " + syscalls)
