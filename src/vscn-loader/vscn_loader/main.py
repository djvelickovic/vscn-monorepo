import os
from time import sleep
from vscn_loader.loader import CVELoaderService
from vscn_loader.nvd import NVDClient
from vscn_loader.repository import Repository
from vscn_loader.transform import CVETransformService
from vscn_loader.filter import CVEFilterService
from dotenv import load_dotenv
from datetime import datetime

def run():

    load_dotenv(".env")
    postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
    postgresql_port = os.getenv("POSTGRES_PORT", "5432")
    postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

    postgresql_username = os.getenv("POSTGRES_USER", "postgresql")
    postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgresql")

    postgresql_db = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"
    
    
    transform_service = CVETransformService()
    filter_service = CVEFilterService()
    nvd_client = NVDClient()
    repository = Repository(postgresql_db)
    
    cve_loader_service = CVELoaderService(transform_service, filter_service, nvd_client, repository)
    
    # last_modified_at = repository.get_last_modified_at()
    # cve_loader_service.load_diff(last_modified_at)
    
    from_date = datetime(2004, 3, 1)
    # cve_loader_service.full_load(from_date)
    cve_loader_service.full_transform(from_date)
    
    

    # if not exists(TMP_DIR):
    #     os.mkdir(TMP_DIR)

    # for year in years:
    #     metadata = download_nvd_metadata(year)
    #     sha256 = metadata.get("sha256")
    #     insert = should_insert(year, sha256, postgresql_db)
    #     print(f"Should insert: {insert}")
    #     if insert:
    #         print(
    #             f"""CVE for the year {year} has changed since the last update.
    #             Proceeding with the update. SHA256: {sha256}"""
    #         )
    #         nvd_path = download_nvd(year)
    #         load_cve(year, nvd_path, sha256, postgresql_db)
    #         load_matchers(year, nvd_path, sha256, postgresql_db)
    #         update_snapshots(year, sha256, postgresql_db)

    #     else:
    #         print(f'Snapshot for the year: {year}, with sha256 {sha256} already inserted. Skipping insertion...')


if __name__ == '__main__':
    run()
