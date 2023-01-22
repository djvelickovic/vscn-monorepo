from vscn_loader.const import TMP_DIR, BIN_DIR
from vscn_loader.runner import run
from repository import Repository
import json


def load_cve(year, nvd_path, sha256, postgresql_db: str):
    final_cve_path = f'{TMP_DIR}/cve-{year}.json'
    output = run([f'{BIN_DIR}/extract-cve.sh', nvd_path, final_cve_path])
    print('Finished command ', output)

    raw_cves = None

    with open(final_cve_path) as f:
        raw_cves = json.load(f)

    cves = _transform(raw_cves, year, sha256)

    with Repository(postgresql_db) as repo:
        repo.insert_cves(cves)

        print(f'Inserted {len(cves)} rows')
        affected_rows = repo.clean_up_cves(year, sha256)
        print(f"Cleaned up: {affected_rows}")


def _transform(cves, year, sha256):
    def enrich_cve(cve):
        cve['year'] = year
        cve['sha256'] = sha256
        return cve
    return list(map(enrich_cve, cves))
