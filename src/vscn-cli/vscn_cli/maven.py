from vscn_cli.runner import run


def scan(project_root_dir):
    _pre_run(project_root_dir)
    return _list_dependencies(project_root_dir)


def _pre_run(project_root_dir):
    pom_path = f'{project_root_dir}/pom.xml'
    run([["mvn", "-f", pom_path, "dependency:list"]])


def _list_dependencies(project_root_dir) -> list:
    pom_path = f'{project_root_dir}/pom.xml'

    std_out = run([
        ["mvn", "-f", pom_path, "dependency:list"],
        ["grep", ":.*:.*:.*"],
        ["cut", "-d", "]", "-f2-"],
        ["sed", "s/:[a-z]*$//g"],
        ["sort", "-u"]
    ]).decode("ascii")

    return _extract_dependencies(std_out)


def _extract_dependencies(std_out: str) -> list:
    lines = std_out.splitlines()
    raw_dependencies = map(lambda line: line.split('--')[0], lines)
    filtered_dependencies = filter(lambda line: not line.endswith('test'), raw_dependencies)

    dependencies = []
    for dependency in filtered_dependencies:
        mapped_dependency = _map_dependency(dependency)
        if mapped_dependency:
            dependencies.append(mapped_dependency)
    return dependencies


def _map_dependency(dependency: str):
    artifactId = None
    dependency_parts = dependency.split(':')

    if len(dependency_parts) in [4, 5]:
        artifactId = dependency_parts[1]
        version = dependency_parts[3]
    elif len(dependency_parts) == 6:
        artifactId = dependency_parts[1]
        version = dependency_parts[4]

    if artifactId:
        return {
            'dependency_name': artifactId.strip(),
            'version': version.strip()
        }
