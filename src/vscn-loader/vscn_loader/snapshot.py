from repository import Repository


def should_insert(year, sha256: str, postgresql_db: str) -> bool:
    with Repository(postgresql_db) as repo:
        return repo.should_insert(year, sha256)


def update_snapshots(year, sha256: str, postgresql_db: str) -> None:
    with Repository(postgresql_db) as repo:
        repo.update_snapshot(year, sha256)
        print(f'Updated snapshot for the year {year} -> {sha256}')
