
from vscnl.const import TMP_DIR
from urllib import request
import zipfile
import requests


def nvd_cve_url(year):
    return f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'


def nvd_meta_url(year):
    return f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta'


def download_nvd(year):
    file_name = f'nvdcve-1.1-{year}.json'
    zip_path = f'{TMP_DIR}{file_name}.zip'
    url = nvd_cve_url(year)

    print(f'loading nvd file from {url}')
    request.urlretrieve(url, zip_path)

    print(f'Extracting {zip_path}')

    extract_zip(zip_path, TMP_DIR)

    return f'{TMP_DIR}{file_name}'


def download_nvd_metadata(year):
    url = nvd_meta_url(year)
    r = requests.get(url)
    lines = r.text.split()
    data = {line.split(':')[0]: line.split(':')[1] for line in lines}
    print(f'Metadata for the year {year} -> {data}')
    return data


def extract_zip(zip_path, destination_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(destination_dir)
