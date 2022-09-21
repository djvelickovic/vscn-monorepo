from pymongo import MongoClient
from dotenv import dotenv_values
import sys
from os.path import exists
import os
from vscnl.const import TMP_DIR
from vscnl.nvd import download_nvd, download_nvd_metadata
from vscnl.snapshot import should_insert, update_snapshots
from vscnl.cve import load_cve
from vscnl.matchers import load_matchers


def normalize_years(years: str):
    return list(map(lambda y: y.strip(), years.split(',')))


years = normalize_years(sys.argv[1])

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
        print(
            f'Snapshot for the year: {year}, with sha256 {sha256} already inserted. Skipping insertion...')

client.close()
