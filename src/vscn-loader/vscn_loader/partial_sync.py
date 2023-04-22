from dotenv import load_dotenv
from vscn_loader.loader import CVELoaderService
from vscn_loader.nvd import NVDClient
from vscn_loader.repository import Repository
from vscn_loader.transform import CVETransformService
from vscn_loader.filter import CVEFilterService

def run():
    load_dotenv(".env")
    
    nvd_client = NVDClient()
    repository = Repository()
    filter_service = CVEFilterService()
    transform_service = CVETransformService(filter_service, repository)
    
    cve_loader_service = CVELoaderService(transform_service, filter_service, nvd_client, repository)
    
    cve_loader_service.diff_load()
    transform_service.partial_transform()

run()