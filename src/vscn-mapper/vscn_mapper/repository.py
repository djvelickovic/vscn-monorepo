from typing import List, Tuple, Dict
import psycopg
import json


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

    def get_unmatched_dependencies(self) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT dependency_name, language
                FROM unmatched_dependencies
                """,
            )
            result = cur.fetchall()
            return list(
                map(lambda row: {"dependency_name": row[0], "language": row[1]}, result)
            )

    def clear_fuzzy_match_results(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM analytics.potential_matches
                """
            )
            self.conn.commit()

    def save_fuzzy_match_results(self, fuzz_map: List[Tuple[str, str, Dict]]) -> None:
        with self.conn.cursor() as cur:
            args_str = ",".join(
                cur.mogrify(
                    "(%s, %s, %s)",
                    (dependency_name, language, json.dumps(potential_matches)),
                )
                for dependency_name, language, potential_matches in fuzz_map
            )

            cur.execute(
                f"""
                INSERT INTO analytics.potential_matches (dependency_name, language, potential_matches)
                VALUES {args_str}
                """
            )
            self.conn.commit()
