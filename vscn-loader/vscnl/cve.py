from pymongo.database import Database
from vscnl.const import TMP_DIR, BIN_DIR
from vscnl.runner import run
import json


def load_cve(year, nvd_path, sha256, db: Database):
    final_cve_path = f'{TMP_DIR}/cve-{year}.json'
    output = run([f'{BIN_DIR}/extract-cve.sh', nvd_path, final_cve_path])
    print('Finished command ', output)

    raw_cves = None

    with open(final_cve_path) as f:
        raw_cves = json.load(f)

    cves = _transform(raw_cves, year, sha256)

    cve_collection = db.get_collection('cve')

    insert_result = cve_collection.insert_many(cves)
    print(f'Inserted {len(cves)} rows: ', insert_result.acknowledged)
    cleanup_result = cve_collection.delete_many({'$and': [{'year': year}, {'sha256': {'$ne': sha256}}]})
    print('Cleaned up: ', cleanup_result.deleted_count)


def _transform(cves, year, sha256):
    def enrich_cve(cve):
        cve['year'] = year
        cve['sha256'] = sha256
        return cve
    return list(map(enrich_cve, cves))
