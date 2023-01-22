from typing import List, Tuple, Dict
import psycopg


class Repository(object):
    def __init__(self, connection_string):
        self.connection_string = connection_string

    def __enter__(self):
        self.conn: psycopg.Connection = psycopg.connect(self.connection_string, cursor_factory=psycopg.ClientCursor)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def get_matchers(self, product: str) -> List[Dict]:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id, year, hash, products, vendors, config, created_at
                FROM matchers
                WHERE products ? %s
                """, (product,))
            result = cur.fetchall()
            return self._map_matcher(result)

    def _map_matcher(self, rows: List[Tuple]):
        matchers = []
        for (id, year, hash, products, vendors, config, created_at) in rows:
            matchers.append({
                "id": id,
                "year": year,
                "hash": hash,
                "products": products,
                "vendors": vendors,
                "config": config,
                "created_at": created_at
            })

        return matchers

    def get_cves(self, cve_ids: List[str]) -> List[Dict]:
        with self.conn.cursor() as cur:
            args = ','.join(cur.mogrify("%s", (cve_id, )) for cve_id in cve_ids)
            cur.execute(f"""
                SELECT cve_id, year, hash, refs, description, severity, published_at, last_modified, created_at
                FROM cves
                WHERE cve_id in ({args})
                """)
            result = cur.fetchall()
            return self._map_cves(result)

    def _map_cves(self, rows: List[Tuple]) -> List[Dict]:
        cves = []
        for (id, year, sha256, refs, description, severity, published_at, last_modified, created_at) in rows:
            cves.append({
                "id": id,
                "year": year,
                "sha256": sha256,
                "refs": refs,
                "description": description,
                "severity": severity,
                "published_at": published_at,
                "last_modified": last_modified
            })
        return cves

    def get_products(self) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT jsonb_array_elements(products)
                FROM matchers
                """
            )
            result = cur.fetchall()
            return list(map(lambda row: row[0], result))
