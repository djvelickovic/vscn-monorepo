from vscn_cli.runner import run
import json


def scan(venv_location):
    _pre_run(venv_location)
    return _list_dependencies(venv_location)


def _pre_run(venv_location):
    run([
        [f"{venv_location}/bin/python",  "-m", "pip", "install", "--upgrade", "pip"]
    ])


def _list_dependencies(venv_location) -> list:
    std_out = run([
        [f"{venv_location}/bin/python",  "-m", "pip", "list", "--format", "json"]
    ])
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
