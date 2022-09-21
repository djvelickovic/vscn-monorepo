from pymongo.database import Database


def should_insert(year, sha256: str, db: Database) -> bool:
    snapshots = db.get_collection('snapshots')
    snapshot_result = snapshots.find_one({'year': year})

    if not snapshot_result:
        return True

    return False

    return snapshot_result['sha256'] != sha256


def update_snapshots(year, sha256: str, db: Database):
    snapshots = db.get_collection('snapshots')
    update_result = snapshots.find_one_and_replace(
        {'year': year}, {'year': year, 'sha256': sha256}, upsert=True)

    print(f'Updated snapshot for the year {year} -> {sha256}. Result: {update_result}')
