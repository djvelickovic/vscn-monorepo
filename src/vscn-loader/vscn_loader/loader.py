import pandas as pd
from datetime import datetime
from time import sleep
from vscn_loader.nvd import NVDClient
from vscn_loader.repository import Repository
from vscn_loader.transform import CVETransformService
from vscn_loader.filter import CVEFilterService


class CVELoaderService(object):
    def __init__(self, transform_service: CVETransformService, filter_service: CVEFilterService, nvd_client: NVDClient, repository: Repository) -> None:
        self.transform_service = transform_service
        self.filter_service = filter_service
        self.nvd_client = nvd_client
        self.repository = repository
    
    def diff_load(self) -> None:
        
        last_modified_at = None
        with self.repository as repo:
            last_modified_at = repo.get_last_modified_cve_raw()
        
        print(f"Found last modified raw cve: {last_modified_at}")
        
        start_date = last_modified_at.strftime('%Y-%m-%dT%H:%M:%S')
        end_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
                
        print(f"Loading modified CVEs from {start_date} until {end_date}")

        start_index = 0
        
        while True:
            # loading page per page for given date span
            
            total_results, returned_results_per_page, cves = self.nvd_client.load_cve_page_by_modified_date(start_date, end_date, start_index)
                            
            print(f"Handling results with offset from {start_index} to {start_index + returned_results_per_page}")
            
            with self.repository as repo:
                repo.upsert_raw_cves(cves)
                
            print(f"Sleeping 6s")
            sleep(6.0)
            
            if total_results > start_index + returned_results_per_page:
                start_index +=  returned_results_per_page
            else:
                break
        
    
    def full_load(self, from_date: datetime) -> None:
        months = pd.date_range(from_date.strftime("%Y-%m-%d"), datetime.now().strftime("%Y-%m-%d"), freq="MS").tolist()
        
        for month in months:
            from_month = month.strftime('%Y-%m-%dT%H:%M:%S')
            until_month = (month + pd.DateOffset(months=1)).strftime('%Y-%m-%dT%H:%M:%S')
            
            print(f"Loading published CVEs from {from_month} until {until_month}")

            start_index = 0
            
            while True:
                # loading page per page for given date span
                
                total_results, returned_results_per_page, cves = self.nvd_client.load_cve_page_by_published_date(from_month, until_month, start_index)
                                
                print(f"Handling results with offset from {start_index} to {start_index + returned_results_per_page}")
                
                with self.repository as repo:
                    repo.upsert_raw_cves(cves)
                    
                print(f"Sleeping 6s")
                sleep(6.0)
                
                if total_results > start_index + returned_results_per_page:
                    start_index +=  returned_results_per_page
                else:
                    break
    



        
        