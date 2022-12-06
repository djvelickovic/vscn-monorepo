from vscn_cli.runner import run
import json


def scan(venv_location):
    _pre_run(venv_location)
    return _list_dependencies(venv_location)


def _pre_run(venv_location):
    run(['pip_pre_run.sh', venv_location])


def _list_dependencies(venv_location) -> list:
    std_out = run(['pip_list.sh', venv_location]).decode('ascii')
    return _extract_dependencies(std_out)


def _extract_dependencies(std_out: str) -> list:
    dependencies = json.loads(std_out)

    result = list(map(_map_dependency, dependencies))

    return result


def _map_dependency(dependency: str):
    return {
        'product': dependency['name'],
        'version': dependency['version']
    }
