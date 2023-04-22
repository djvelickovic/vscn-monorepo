import re
from vscn_server.repository import Repository
from typing import List, Dict


class TransformService(object):
    def __init__(self, connection_string) -> None:
        self.connection_string = connection_string

    def transform(self, dependencies: List, language: str) -> List:
        result = []

        for dependency in dependencies:
            dependency_name = dependency["dependency_name"]
            version = dependency["version"]
            transformed_dependencies = self._transform_dependency(
                dependency_name, version, language
            )
            result.extend(transformed_dependencies)

        return result

    def _transform_dependency(self, dependency_name: str, version: str, language: str):
        if dependency_name is None or dependency_name == "":
            raise Exception("Missing dependency name")
        if version is None or version == "":
            raise Exception("Missing version")

        if self._should_skip_dependency(version):
            return []

        sanitized_version = self._sanitize_version(version)
        mapped_product_names = self._get_mapped_product_names(dependency_name, language)

        transformed_products = []
        for product_name in mapped_product_names:
            transformed_products.append(
                {
                    "product_name": product_name,
                    "dependency_name": dependency_name,
                    "version": sanitized_version,
                }
            )

        return transformed_products

    def _get_mapped_product_names(self, dependency_name: str, language: str) -> List:
        mapped_products = []

        with Repository(self.connection_string) as repo:
            mapped_products = repo.get_product_mappings(dependency_name, language)

        if len(mapped_products) > 0:
            return mapped_products
        else:
            return [dependency_name]

    def _should_skip_dependency(self, version: str) -> bool:
        return version.endswith("SNAPSHOT")

    def _sanitize_version(self, version: str):
        version_without_characters = re.sub(r"[a-zA-Z]", "", version)
        if version_without_characters.endswith(
            "."
        ) or version_without_characters.endswith("-"):
            return version_without_characters[0:-1]
        return version_without_characters
