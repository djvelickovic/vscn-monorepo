
import re
from vscn_server.repository import Repository
from typing import List


class TransformService(object):
    def __init__(self, connection_string) -> None:
        self.connection_string = connection_string

    def transform(self, dependencies: list) -> list:
        result = []
        for dependency in dependencies:
            transformed_dependencies = self.__transform_dependency(dependency)
            result.extend(transformed_dependencies)

        return result

    def __transform_dependency(self, dependency):
        product = dependency['product']
        version = dependency['version']

        if self.__should_skip_dependency(dependency):
            return []

        sanitized_version = self.__sanitize_version(version)
        products = self.__transform_products(product)

        def build_product_object(p):
            return {
                'product': p,
                'original_product': product,
                'version': sanitized_version
            }

        return list(map(build_product_object, products))

    def _get_mapping(self, product_name: str) -> List[str]:
        with Repository(self.connection_string) as repo:
            return repo.get_product_mappings(product_name)

    def __transform_products(self, product) -> list:
        mapped_products = self._get_mapping(product)
        if len(mapped_products) > 0:
            return mapped_products
        else:
            return [product]

    def __should_skip_dependency(self, dependency) -> bool:
        return dependency['version'].endswith('SNAPSHOT')

    def __sanitize_version(self, version: str):
        version_without_characters = re.sub(r'[a-zA-Z]', '', version)
        if version_without_characters.endswith('.') or version_without_characters.endswith('-'):
            return version_without_characters[0:-1]
        return version_without_characters
