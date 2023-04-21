import requests
from typing import Tuple, Any
from time import sleep

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
# CVE_UPDATE_URL_TEMPLATE = "?noRejected&lastModStartDate={}&lastModEndDate={}&resultsPerPage={}&startIndex={}"
# CVE_LOAD_URL_TEMPLATE = "https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&pubStartDate={}&pubEndDate={}&resultsPerPage={}&startIndex={}"
PAGE_SIZE = 2000
EXAMPLE1 = "2022-03-01T13:00:00.000"
EXAMPLE2 = "2022-06-01T13:00:00.000"


class NVDClient(object):
    def __init__(self, base_url: str = NVD_BASE_URL, page_size: int = PAGE_SIZE) -> None:
        self.base_url = base_url
        self.page_size = page_size
        self.retry = 3

    def _request_with_retry(self, url: str):
        # TODO: implement retry
        
        for i in range(1, self.retry + 2):
            response = requests.get(url)
            if response.status_code != 200 and i != self.retry:
                backoff_sleep = i * 3.0
                print(f"Received status code {response.status_code}, retrying {i}. time, next retry in {backoff_sleep}s")
                sleep(backoff_sleep)
            else:
                return response
        
        raise Exception("Retry number exceeded.")
            

    def load_cve_page(self, published_start_date: str, published_end_date: str, start_index: int) -> Tuple[int, int, Any]:
        url = f"{NVD_BASE_URL}?pubStartDate={published_start_date}&pubEndDate={published_end_date}&resultsPerPage={self.page_size}&startIndex={start_index}"
        print(f"Getting CVEs from: {url}")
        response = self._request_with_retry(url)
        cve_data = response.json()
        returned_results_per_page = cve_data.get("resultsPerPage")
        total_results = cve_data.get("totalResults")
        
        return (total_results, returned_results_per_page, cve_data.get("vulnerabilities"))
    
