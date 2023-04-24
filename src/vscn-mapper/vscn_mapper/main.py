import os
from dotenv import load_dotenv
from vscn_mapper.mapper import MapperService


def run():
    load_dotenv(".env")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
    postgresql_port = os.getenv("POSTGRES_PORT", "5432")
    postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

    postgresql_username = os.getenv("POSTGRES_USER", "postgres")
    postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgres")

    postgresql_url = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"

    mapper_service = MapperService(postgresql_url)
    mapper_service.run_unknown_mapper(similarity=80)


if __name__ == "__main__":
    run()
