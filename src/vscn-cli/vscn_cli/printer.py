from termcolor import cprint, colored


def print_info(project_type, relative_root_path):
    cprint(
        "---------------- [ Scanning Project -> Type: {}, Path: {}] ----------------".format(
            project_type, relative_root_path
        ),
        "blue",
    )


def print_pre_scan_summary(dependencies_for_scanning: list):
    print(f'Found {len(dependencies_for_scanning)} dependencies')
    # for d in sorted(dependencies_for_scanning, key=lambda d: d["dependency_name"]):
    #     cprint("{} ({})".format(d["dependency_name"], d["version"]), "white")


def print_found_info(affected_dependencies: list):
    cprint("---------------- [ Scanning Result ] ----------------", "blue")

    for dependency in affected_dependencies:
        dependency_name = dependency["dependency"]["dependency_name"]
        product_name = dependency["dependency"]["product_name"]
        version = dependency["dependency"]["version"]
        number_of_vulnerabilities = len(dependency["vulnerabilities"])
        print(
            colored(
                f"{dependency_name} ({product_name}) - {version}",
                "red",
            ),
            "has",
            colored(number_of_vulnerabilities, "red"),
            "vulnerabilities",
        )
    
    unique_vulnerabilities = get_unique_vulnerabilities(affected_dependencies)
    total_number = len(unique_vulnerabilities)

    cprint(f"Found total: {total_number}", "red")

def get_unique_vulnerabilities(affected_dependencies):
    cves = set()
    for dependency in affected_dependencies:
        for vulnerability in dependency.get("vulnerabilities", []):
            cves.add(vulnerability["id"])
    return cves

def print_cve_details(affected_dependencies):
    cprint("---------------- [ CVE Details] ----------------\n", "blue")

    for dependency in affected_dependencies:
        dependency_name = dependency["dependency"]["dependency_name"]
        product_name = dependency["dependency"]["product_name"]
        version = dependency["dependency"]["version"]
        vulnerabilities = dependency["vulnerabilities"]

        cprint(f"[*] {dependency_name} ({version})\n", "red")
        for vulnerability in vulnerabilities:
            id = vulnerability["id"]
            # severity = vulnerability["severity"]
            desc = vulnerability["description"]
            ref = vulnerability["refs"]
            published = vulnerability["published_at"]

            cprint(f"[*] {dependency_name} ({version})\n", "yellow")
            cprint(f"CVE: {id}\n", "yellow")
            cprint(f"Published: {published}", "light_grey")
            cprint(f"CVE Product Name: {product_name}", "light_grey")
            # cprint(f"Severity: {severity}", "light_grey")
            cprint("")
            cprint(f"{desc}\n")
            cprint("References:\n{}\n\n".format("\n".join(ref)), "light_grey")
