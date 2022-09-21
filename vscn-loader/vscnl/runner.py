import subprocess


def run(command: list):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        raise Exception(f'Unable to run command: {command}')
    return stdout
