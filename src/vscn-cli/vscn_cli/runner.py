from subprocess import Popen, PIPE
from typing import List


def run(commands: List[List]):
    # print(f"running command: {commands}")

    process: Popen = Popen(commands[0], stdout=PIPE, stderr=PIPE)
    if len(commands) > 1:
        for command in commands[1:]:
            process = Popen(command, stdin=process.stdout, stdout=PIPE, stderr=PIPE)

    stdout, stderr = process.communicate()
    # print(stdout.decode('ascii'))
    if stderr:
        raise Exception(f'Unable to run command: {command}. Error: {stderr}')
    return stdout
