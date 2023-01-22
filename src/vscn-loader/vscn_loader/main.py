import os
from os.path import exists
from vscn_loader.const import TMP_DIR
from vscn_loader.nvd import download_nvd, download_nvd_metadata
from vscn_loader.snapshot import should_insert, update_snapshots
from vscn_loader.cve import load_cve
from vscn_loader.matchers import load_matchers


def normalize_years(years: str):
    return list(map(lambda y: y.strip(), years.split(',')))


def run():
    postgresql_db = os.getenv('POSTGRESQL_DB', default="postgresql://postgresql:postgresql@localhost:5432/vscn")
    years = normalize_years(os.getenv("YEARS", default="2023"))

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
    run()
