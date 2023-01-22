from typing import List
from vscn_server.repository import Repository


class CveService(object):
    def __init__(self, connection_string: str):
        self.connection_string = connection_string

    def get_cves(self, cve_ids: List[str]):
        with Repository(self.connection_string) as repo:
            return repo.get_cves(cve_ids)
