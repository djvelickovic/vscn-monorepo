from vscnc import maven, pip, client, printer, const
from os import path
import click


@click.group()
def cli():
    pass


@cli.command()
@click.option('-u', '--url', type=str, help='Type of the project', default='http://localhost:11001')
@click.option('-t', '--type', type=str, help='Type of the project', required=True)
@click.option('-d', '--dir', type=str, help='Root of the project', required=True)
def scan(url, type, dir):

    printer.print_info(type, dir)

    if not validate_project_type(type):
        print('Error project type')
        return

    if not validate_root_dir(dir):
        print('Error root dir')
        return

    dependencies_for_scanning = _get_dependencies_for_scanning(type, dir)
    printer.print_pre_scan_summary(dependencies_for_scanning)
    affected_dependencies = client.scan(url, dependencies_for_scanning)
    cves_list = map(lambda d: d['vulnerabilities'], affected_dependencies)

    cves = set()

    for c in cves_list:
        cves.update(c)

    if len(cves) > 0:
        cve_details = client.load_cve(url, cves)
        printer.print_cve_details(affected_dependencies, cve_details)

    printer.print_found_info(affected_dependencies)


def validate_project_type(project_type) -> bool:
    return project_type in const.SUPPORTED_PROJECT_TYPES


def validate_root_dir(relative_root_path) -> bool:
    if path.exists(relative_root_path) and path.isdir(relative_root_path):
        return True
    return False


def _get_dependencies_for_scanning(type, relative_path):
    if type == 'mvn':
        return maven.scan(relative_path)
    if type == 'pip':
        return pip.scan(relative_path)
    return None
