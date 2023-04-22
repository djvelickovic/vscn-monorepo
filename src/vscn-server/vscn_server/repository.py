from typing import List, Tuple, Dict, Set
import psycopg


class Repository(object):
    def __init__(self, connection_string):
        self.connection_string = connection_string

    def __enter__(self):
        self.conn: psycopg.Connection = psycopg.connect(
            self.connection_string, cursor_factory=psycopg.ClientCursor
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def fetch_potential_cves(self, product_name: str) -> List[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    source_identifier,
                    published_at,
                    last_modified_at,
                    vulnerability_status,
                    description,
                    weaknesses,
                    configurations,
                    refs,
                    products,
                    vendors,
                    types
                FROM cves
                WHERE products ? %s
                """,
                (product_name,),
            )
            result = cur.fetchall()
            return self._map_matcher(result)

    def _map_matcher(self, rows: List[Tuple]):
        matchers = []
        for row in rows:
            id, source_identifier, published_at, last_modified_at, vulnerability_status, description, weaknesses, configurations, refs, products, vendors, types = row
            
            matchers.append(
                {
                    "id": id,
                    "source_identifier": source_identifier,
                    "published_at": published_at,
                    "last_modified_at": last_modified_at,
                    "vulnerability_status": vulnerability_status,
                    "description": description,
                    "weaknesses": weaknesses,
                    "configurations": configurations,
                    "refs": refs,
                    "products": products,
                    "vendors": vendors,
                    "types": types
                }
            )

        return matchers

    def get_products(self) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT jsonb_array_elements(products)
                FROM cves
                """
            )
            result = cur.fetchall()
            return list(map(lambda row: row[0], result))

    def insert_unmatched_dependencies(self, unmatched_dependencies: Set[Tuple[str, str]], language: str, package_manager: str) -> int:
        with self.conn.cursor() as cur:
            
            args_str = ",".join(
                cur.mogrify("(%s, %s, %s, %s)", (product_name, version, language, package_manager))
                for product_name, version in unmatched_dependencies
            )
            
            cur.execute(
                f"""
                INSERT INTO unmatched_dependencies (product_name, version, language, package_manager)
                VALUES {args_str}
                """
            )
            self.conn.commit()
            return cur.rowcount

    #TODO: make bulk fetch
    def get_product_mappings(self, dependency_name: str, language: str) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT product_name
                FROM dependency_product_mappings
                WHERE dependency_name = %s AND language = %s
                """,
                (dependency_name, language),
            )
            result = cur.fetchall()
            return list(map(lambda row: row[0], result))
