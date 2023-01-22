from typing import List
import json
import psycopg


class Repository(object):
    def __init__(self, connection_string):
        self.connection_string = connection_string

    def __enter__(self):
        self.conn: psycopg.Connection = psycopg.connect(self.connection_string, cursor_factory=psycopg.ClientCursor)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def insert_matchers(self, matchers: List):
        with self.conn.cursor() as cur:
            args_str = ','.join(cur.mogrify(
                '(%s, %s, %s, %s, %s, %s)',
                (
                    matcher['id'], matcher['year'],
                    matcher['sha256'],
                    json.dumps(matcher.get('products', [])),
                    json.dumps(matcher.get('vendors', [])),
                    json.dumps(matcher.get('config', {}))
                )
            ) for matcher in matchers)

            cur.execute(f"""
                INSERT INTO matchers (cve_id, year, hash, products, vendors, config)
                VALUES {args_str}
                """)

        self.conn.commit()

    def insert_cves(self, cves: List) -> int:
        with self.conn.cursor() as cur:
            args_str = ','.join(
                cur.mogrify(
                    '(%s, %s, %s, %s, %s, %s, %s, %s)',
                    (cve['id'],
                     json.dumps(cve.get('ref', [])),
                     cve['desc'],
                     cve['severity'],
                     cve['published'],
                     cve['lastModified'],
                     cve['year'],
                     cve['sha256'])) for cve in cves)

            cur.execute(f"""
                INSERT INTO cves (cve_id, refs, description, severity, published_at, last_modified, year, hash)
                VALUES {args_str}
                """)
            self.conn.commit()
            return cur.rowcount

    def clean_up_cves(self, year: int, sha256: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM cves WHERE year = %s and hash != %s", (year, sha256))
            self.conn.commit()
            return cur.rowcount

    def clean_up_matchers(self, year: int, sha256: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM matchers WHERE year = %s and hash != %s", (year, sha256))
            self.conn.commit()
            return cur.rowcount

    def should_insert(self, year: int, sha256: str) -> bool:
        with self.conn.cursor() as cur:
            cur.execute('SELECT year, hash FROM snapshots WHERE year = %s AND hash = %s', (year, sha256))
            result = cur.fetchone()
            self.conn.commit()
            return result is None

    def update_snapshot(self, year: int, sha256: str):
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO snapshots (year, hash, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT(year)
                DO
                    UPDATE SET year = %s, hash = %s, updated_at = now()
            """, (year, sha256, year, sha256))
            self.conn.commit()
            return cur.rowcount
