import os
from os.path import exists
from time import sleep
from vscn_loader.const import TMP_DIR
from vscn_loader.nvd import download_nvd, download_nvd_metadata
from vscn_loader.snapshot import should_insert, update_snapshots
from vscn_loader.cve import load_cve
from vscn_loader.matchers import load_matchers
from dotenv import load_dotenv


def normalize_years(years: str):
    return list(map(lambda y: y.strip(), years.split(',')))


def run():

    load_dotenv(".env")
    postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
    postgresql_port = os.getenv("POSTGRES_PORT", "5432")
    postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

    postgresql_username = os.getenv("POSTGRES_USER", "postgresql")
    postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgresql")

    postgresql_db = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"
    years = normalize_years(os.getenv("YEARS", default="2022"))

    print(f"Inserting for years: {years}")

    if not exists(TMP_DIR):
        os.mkdir(TMP_DIR)

    for year in years:
        metadata = download_nvd_metadata(year)
        sha256 = metadata.get("sha256")
        insert = should_insert(year, sha256, postgresql_db)
        print(f"Should insert: {insert}")
        if insert:
            print(
                f"""CVE for the year {year} has changed since the last update.
                Proceeding with the update. SHA256: {sha256}"""
            )
            nvd_path = download_nvd(year)
            load_cve(year, nvd_path, sha256, postgresql_db)
            load_matchers(year, nvd_path, sha256, postgresql_db)
            update_snapshots(year, sha256, postgresql_db)

        else:
            print(f'Snapshot for the year: {year}, with sha256 {sha256} already inserted. Skipping insertion...')


if __name__ == '__main__':
    sleep(5)
    run()
