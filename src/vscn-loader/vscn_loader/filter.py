

class CVEFilterService(object):
    
    def filter(self, cves):
        filtered_cves = []
        for cve in cves:
            if self._should_filter(cve):
                filtered_cves.append(cve)
        return filtered_cves
    
    def _should_filter(self, cve) -> bool:
        types: list = cve['types']
        vulnerability_status: str = cve['vulnerability_status']
        return 'a' in types and vulnerability_status.lower() != 'rejected'
