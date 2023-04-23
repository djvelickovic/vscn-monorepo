import requests


def scan(url, dependencies: list, package_manager: str, language: str):
    request = {
        "metadata": {
            "operating_system": {"name": "n/a", "version": "n/a"},
            "language": language,
            "package_manager": package_manager
        },
        "dependencies": dependencies,
    }

    response = requests.post(f"{url}/vscn/scan", json=request)

    if response.status_code != 200:
        raise Exception(f"Error received from the server. {response.status_code}")

    return response.json()
