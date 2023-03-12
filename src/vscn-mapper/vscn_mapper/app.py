import os
from threading import Thread
from flask import Flask
from dotenv import load_dotenv
from vscn_mapper.mapper import MapperService


load_dotenv('.env')
debug = os.environ.get('DEBUG', 'false').lower() == 'true'
postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
postgresql_port = os.getenv("POSTGRES_PORT", "5432")
postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

postgresql_username = os.getenv("POSTGRES_USER", "postgres")
postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgres")

postgresql_url = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"

app = Flask(__name__)

mapper_service = MapperService(postgresql_url)


@app.get('/healthz')
def health():
    return {}


@app.get('/matcher/run')
def scan():
    t = Thread(target=mapper_service.run_unknown_mapper, args=(50,))
    t.start()
    return {}


mapper_service.run_unknown_mapper(50)
