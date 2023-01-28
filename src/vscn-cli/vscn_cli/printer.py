from termcolor import cprint, colored


def print_info(project_type, relative_root_path):
    cprint(
        '---------------- [ Scanning Project -> Type: {}, Path: {}] ----------------'
        .format(project_type, relative_root_path), 'blue')


def print_pre_scan_summary(dependencies_for_scanning: list):
    for d in sorted(dependencies_for_scanning, key=lambda d: d['product']):
        cprint('{} ({})'.format(d['product'], d['version']), 'white')


def print_found_info(affected_dependencies: list):
    cprint('---------------- [ Scanning Result ] ----------------', 'blue')

    for d in sorted(affected_dependencies, key=lambda d: len(d['vulnerabilities']), reverse=True):
        number_of_vulnerabilities = len(d['vulnerabilities'])
        dependency = d['dependency']
        print(colored('{} ({})'.format(dependency['original_product'], dependency['version']), 'red'),
              'has', colored(number_of_vulnerabilities, 'red'),
              'vulnerabilities')

    total_number = sum(map(lambda v: len(v['vulnerabilities']), affected_dependencies))

    cprint(f'Found total: {total_number}', 'red')


def print_cve_details(affected_dependencies, cves):
    cprint('---------------- [ CVE Details] ----------------\n', 'blue')

    for d in sorted(affected_dependencies, key=lambda d: len(d['vulnerabilities']), reverse=True):
        vulnerabilities = sorted(d['vulnerabilities'], reverse=True)
        dependency = d['dependency']

        cve_product = dependency['product']
        original_product = dependency['original_product']
        version = dependency['version']

        cprint(f'[*] {original_product} ({version})\n', 'red')
        for id in vulnerabilities:

            cve = cves.get(id)
            severity = cve['severity']
            desc = cve['description']
            ref = cve['refs']
            published = cve['published_at']

            cprint(f'[*] {original_product} ({version})\n', 'yellow')
            cprint(f'CVE: {id}\n', 'yellow')
            cprint(f'Published: {published}', 'light_grey')
            cprint(f'CVE Name: {cve_product}', 'light_grey')
            cprint(f'Severity: {severity}', 'light_grey')
            cprint('')
            cprint(f'{desc}\n')
            cprint('References:\n{}\n\n'.format('\n'.join(ref)), 'light_grey')
