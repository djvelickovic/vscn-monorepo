from vscn_cli import maven, pip, client, printer, const
from os import path
import click
from halo import Halo


@click.group()
def cli():
    pass


@cli.command()
@click.option(
    "-u",
    "--url",
    type=str,
    help="Url of the backend service",
    default="http://localhost:11001",
)
@click.option("-t", "--type", type=str, help="Package Manager", required=True)
@click.option(
    "-d", "--dir", type=str, help="Root directory of the project", required=True
)
def scan(url, type, dir):
    printer.print_info(type, dir)

    if not validate_project_type(type):
        print("Error project type")
        return

    if not validate_root_dir(dir):
        print("Error root dir")
        return

    language = get_language(type)

    maven_spinner = Halo(text='Listing Maven Dependencies', spinner='bouncingBall')
    maven_spinner.start()
    
    dependencies_for_scanning = get_dependencies_for_scanning(type, dir)

    maven_spinner.stop()

    printer.print_pre_scan_summary(dependencies_for_scanning)

    server_spinner = Halo(text='Checking dependencies', spinner='bouncingBall')
    server_spinner.start()

    affected_dependencies = client.scan(url, dependencies_for_scanning, type, language)
    
    server_spinner.stop()

    
    if len(affected_dependencies) > 0:
        printer.print_cve_details(affected_dependencies)

    printer.print_found_info(affected_dependencies)


def validate_project_type(project_type) -> bool:
    return project_type in const.SUPPORTED_PROJECT_TYPES


def validate_root_dir(relative_root_path) -> bool:
    return path.exists(relative_root_path) and path.isdir(relative_root_path)


def get_language(type):
    if type == "mvn":
        return "java"
    if type == "pip":
        return "python"
    return None


def get_dependencies_for_scanning(type, relative_path):
    if type == "mvn":
        return maven.scan(relative_path)
    if type == "pip":
        return pip.scan(relative_path)
    return None
