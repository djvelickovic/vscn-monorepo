from typing import List, Dict
from packaging import version
from vscn_server.repository import Repository


class ScanService(object):
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        with Repository(connection_string) as repo:
            self.products_set = set(repo.get_products())

    def scan(self, dependencies: List, metadata: Dict) -> List:
        results = []
        unmatched_dependencies = set()

        for dependency in dependencies:
            product_name = dependency["product_name"]
            dependency_name = dependency["dependency_name"]
            version = dependency["version"]

            # do not even bother searching if product doesn't exist in database
            if product_name not in self.products_set:
                # product_name is dependency_name if it doesn't exist in global map
                unmatched_dependencies.add((product_name, version))
                continue

            potential_cves = self._fetch_potential_cves(product_name)
            matched_cves = self._filter_potential_cves(
                product_name, version, potential_cves
            )

            print(
                f"Dependency: {dependency_name} with product name: {product_name} and version: {version} has {len(matched_cves)} vulnerabilities"
            )

            transformed_cves = self._transform_cve_results(matched_cves)

            if len(transformed_cves) > 0:
                results.append(
                    {
                        "dependency": dependency,
                        "vulnerabilities": sorted(
                            transformed_cves,
                            key=lambda cve: (None, cve["id"]),
                            reverse=False,
                        ),
                    }
                )

        if len(unmatched_dependencies) > 0:
            with Repository(self.connection_string) as conn:
                conn.insert_unmatched_dependencies(
                    unmatched_dependencies,
                    metadata["language"],
                    metadata["package_manager"],
                )

        return results

    def _transform_cve_results(self, cves: List):
        transformed_cves = []
        for cve in cves:
            transformed_cve = {
                "id": cve["id"],
                "published_at": cve["published_at"],
                "last_modified_at": cve["last_modified_at"],
                "vulnerability_status": cve["vulnerability_status"],
                "source_identifier": cve["source_identifier"],
                "weaknesses": cve["weaknesses"],
                "description": cve["description"],
                "refs": cve["refs"],
                "configurations": cve["configurations"],   
            }
            transformed_cves.append(transformed_cve)
        return transformed_cves

    def _fetch_potential_cves(self, product_name: str) -> List:
        with Repository(self.connection_string) as repo:
            result = repo.fetch_potential_cves(product_name)
            return result

    def _filter_potential_cves(
        self, product_name, version, potential_cves: List
    ) -> List:
        relevant_cves = []
        for potential_cve in potential_cves:
            if self.traverse_cve(product_name, version, potential_cve):
                relevant_cves.append(potential_cve)

        return relevant_cves

    def traverse_cve(self, product_name, version, cve):
        configurations = cve.get("configurations", [])
        for configuration in configurations:
            for node in configuration:
                if self.traverse_node(product_name, version, node):
                    return True
        return False

    def traverse_node(self, product_name, version, node):
        cpe_match = node["cpeMatch"]
        operator = node["operator"]
        negate = node["negate"]

        if len(cpe_match) == 0:
            return False

        result: bool = None

        if operator == "OR":
            result = False
            for cpe in cpe_match:
                if self.has_cpe_match(product_name, version, cpe):
                    result = True
                    break
        elif operator == "AND":
            result = True
            for cpe in cpe_match:
                if not self.has_cpe_match(product_name, version, cpe):
                    result = False
                    break

        return not result if negate else result

    def has_cpe_match(self, product_name, version, cpe: dict):
        version_start_including = cpe.get("versionStartIncluding")
        version_end_including = cpe.get("versionEndIncluding")
        version_start_excluding = cpe.get("versionStartExcluding")
        version_end_excluding = cpe.get("versionEndExcluding")
        exact_version = cpe.get("exactVersion")
        product = cpe.get("product")
        vulnerable = cpe.get("vulnerable", False)

        if product != product_name:
            return False

        if not vulnerable:
            return False

        if (
            not version_start_including
            and not version_start_excluding
            and not version_end_including
            and not version_end_excluding
            and exact_version in ("*", "-")
        ):
            return True

        upper_bound_version = (
            version_end_including if version_end_including else version_end_excluding
        )
        upper_bound_including = True if version_end_including else False

        lower_bound_version = (
            version_start_including
            if version_start_including
            else version_start_excluding
        )
        lower_bound_including = True if version_start_including else False

        if upper_bound_version or lower_bound_version:
            return is_between(
                upper_bound_version,
                upper_bound_including,
                lower_bound_version,
                lower_bound_including,
                version,
            )
        if exact_version:
            return exact_match(exact_version, version)

        return True


def is_between(
    upper_bound_version,
    upper_bound_including,
    lower_bound_version,
    lower_bound_including,
    current_version,
):
    match_lower_bound = True
    match_upper_bound = True

    parsed_version = version.parse(current_version)

    if lower_bound_version:
        parsed_lower_bound = version.parse(lower_bound_version)
        match_lower_bound = (
            parsed_lower_bound <= parsed_version
            if lower_bound_including
            else parsed_lower_bound < parsed_version
        )

    if upper_bound_version:
        parsed_upper_bound = version.parse(upper_bound_version)
        match_upper_bound = (
            parsed_upper_bound >= parsed_version
            if upper_bound_including
            else parsed_upper_bound > parsed_version
        )

    return match_lower_bound and match_upper_bound


def exact_match(exact_version, current_version):
    return version.parse(exact_version) == version.parse(current_version)
