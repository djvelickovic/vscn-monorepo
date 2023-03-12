from typing import List
import psycopg
import json


class Repository(object):
    def __init__(self, connection_string):
        self.connection_string = connection_string

    def __enter__(self):
        self.conn: psycopg.Connection = psycopg.connect(self.connection_string, cursor_factory=psycopg.ClientCursor)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

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

    def get_unknown_products(self) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT product_name
                FROM unknown_products
                """,
            )
            result = cur.fetchall()
            return list(map(lambda row: row[0], result))

    def clear_fuzzy_match_results(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM unknown_product_mappings
                """)
            self.conn.commit()

    def save_fuzzy_match_results(self, fuzz_map: List) -> None:

        with self.conn.cursor() as cur:
            args_str = ','.join(cur.mogrify(
                '(%s, %s)',
                (
                    matcher[0],
                    json.dumps(matcher[1]),
                )
            ) for matcher in fuzz_map)

            cur.execute(f"""
                INSERT INTO unknown_product_mappings (unknown_product_name, potential_matches)
                VALUES {args_str}
                """)
            self.conn.commit()
