import sys
import os
from os.path import exists
from pymongo import MongoClient
from dotenv import dotenv_values
from vscn_loader.const import TMP_DIR
from vscn_loader.nvd import download_nvd, download_nvd_metadata
from vscn_loader.snapshot import should_insert, update_snapshots
from vscn_loader.cve import load_cve
from vscn_loader.matchers import load_matchers


def normalize_years(years: str):
    return list(map(lambda y: y.strip(), years.split(',')))


def run():
    years = []

    if len(sys.argv) > 1:
        years = normalize_years(sys.argv[1])
    else:
        years = normalize_years(os.getenv("YEARS", default="2022"))

    print(years)

    config = dotenv_values('.env')
    mongo_db_url = config['MONGO_DB_URL']
    mongo_db_name = config['MONGODB_DATABASE_NAME']

    client = MongoClient(mongo_db_url)
    database = client.get_database(mongo_db_name)

    if not exists(TMP_DIR):
        os.mkdir(TMP_DIR)

    for year in years:
        metadata = download_nvd_metadata(year)
        sha256 = metadata.get("sha256")
        insert = should_insert(year, sha256, database)
        if insert:
            print(
                f'CVE for the year {year} has changed since the last update. Proceeding with the update. SHA256: {sha256}')
            nvd_path = download_nvd(year)
            load_cve(year, nvd_path, sha256, database)
            load_matchers(year, nvd_path, sha256, database)
            update_snapshots(year, sha256, database)

        else:
            print(f'Snapshot for the year: {year}, with sha256 {sha256} already inserted. Skipping insertion...')

    client.close()


if __name__ == '__main__':
    run()
