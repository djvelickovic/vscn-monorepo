from flask import Flask, request
from vscn_server.scan import ScanService
from vscn_server.transform import TransformService
from dotenv import load_dotenv
import os


def create_app():
    load_dotenv(".env")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
    postgresql_port = os.getenv("POSTGRES_PORT", "5432")
    postgresql_database = os.getenv("POSTGRES_DATABASE", "vscn")

    postgresql_username = os.getenv("POSTGRES_USER", "postgres")
    postgresql_password = os.getenv("POSTGRES_PASSWORD", "postgres")

    postgresql_url = f"postgresql://{postgresql_username}:{postgresql_password}@{postgresql_host}:{postgresql_port}/{postgresql_database}"

    app = Flask(__name__)

    scan_service = ScanService(postgresql_url)
    transform_service = TransformService(postgresql_url)

    @app.get("/healthz")
    def health():
        return {}

    @app.post("/vscn/scan")
    def scan():
        request_body = request.get_json()

        dependencies = request_body["dependencies"]

        language = request_body["metadata"]["language"]
        package_manager = request_body["metadata"]["package_manager"]
        os_name = request_body["metadata"]["operating_system"]["name"]
        os_version = request_body["metadata"]["operating_system"]["version"]

        metadata = {
            "language": language,
            "package_manager": package_manager,
            "os_name": os_name,
            "os_version": os_version,
        }

        transformed_dependencies = transform_service.transform(dependencies, language)

        # dependency_dict = {dependency['product_name']: dependency for dependency in transformed_dependencies}

        response = scan_service.scan(transformed_dependencies, metadata)
        return response

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=11001)
