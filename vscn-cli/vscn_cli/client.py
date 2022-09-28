import requests


def scan(url, dependencies: list):

    request = {
        'dependencies': dependencies,
    }

    response = requests.post(f'{url}/vscn/scan', json=request)

    if response.status_code != 200:
        raise Exception(f'Error received from the server. {response.status_code}')

    return response.json()


def load_cve(url, cves: set):
    query_params = '&'.join(map(lambda c: f'id={c}', cves))
    response = requests.get(f'{url}/vscn/cve?{query_params}')
    return {cve['id']: cve for cve in response.json()}
