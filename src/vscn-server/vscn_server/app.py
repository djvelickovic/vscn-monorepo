from flask import Flask, request
from vscn_server.matchers import ScanService
from vscn_server.cves import CveService
from vscn_server.transform import TransformService
from dotenv import load_dotenv
import os
from vscn_server.repository import Repository

load_dotenv('.env')
debug = os.environ.get('DEBUG', 'false').lower() == 'true'
postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
postgresql_port = os.getenv("POSTGRES_PORT", "5432")
postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

postgresql_username = os.getenv("POSTGRES_USER", "postgres")
postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgres")

postgresql_url = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"

app = Flask(__name__)

with Repository(postgresql_url) as repo:
    products_set = set(repo.get_products())

cve_service = CveService(postgresql_url)
scan_service = ScanService(products_set, postgresql_url)
transform_service = TransformService()


@app.post('/vscn/scan')
def scan():
    request_body = request.get_json()
    transformed_dependencies = transform_service.transform(request_body['dependencies'])
    dependecy_dict = {dependency['product']: dependency for dependency in transformed_dependencies}
    response = scan_service.scan(dependecy_dict)
    return response


@app.get('/vscn/cve')
def cve():
    cve_ids = request.args.getlist('id')
    return cve_service.get_cves(cve_ids)
