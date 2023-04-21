from typing import List, Tuple, Dict
import json
import psycopg
from datetime import datetime


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

    def get_last_modified_at(self) -> datetime:
        pass
        # with self.conn.cursor() as cur:

    def get_last_modified_at(self) -> datetime:
        pass
        # with self.conn.cursor() as cur:

    def load_raw_cves(self, cves) -> int:
        with self.conn.cursor() as cur:
            args_str = ",".join(
                cur.mogrify(
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        cve["cve"]["id"],
                        cve["cve"]["sourceIdentifier"],
                        cve["cve"]["published"],
                        cve["cve"]["lastModified"],
                        cve["cve"]["vulnStatus"],
                        json.dumps(
                            cve["cve"].get("descriptions")
                            if cve["cve"].get("descriptions") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve["cve"].get("metrics")
                            if cve["cve"].get("metrics") not in (None, "")
                            else {}
                        ),
                        json.dumps(
                            cve["cve"].get("weaknesses")
                            if cve["cve"].get("weaknesses") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve["cve"].get("configurations")
                            if cve["cve"].get("configurations") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve["cve"].get("references")
                            if cve["cve"].get("references") not in (None, "")
                            else []
                        ),
                    ),
                )
                for cve in cves
            )

            # cur.execute(
            #     f"""
            #     INSERT INTO cves_raw (id, source_identifier, published_at, last_modified_at, vulnerability_status, descriptions, metrics, weaknesses, configurations, refs)
            #     VALUES {args_str}
            #     """
            # )
            cur.execute(
                f"""
                WITH 
                
                cve_tmp AS (
                    SELECT * FROM (
                        VALUES
                            {args_str}
                        ) 
                        AS temporary_cte (id, source_identifier, published_at, last_modified_at, vulnerability_status, descriptions, metrics, weaknesses, configurations, refs)
                )
                
                MERGE INTO cves_raw cr
                USING cve_tmp ct
                ON cr.id = ct.id
                WHEN MATCHED THEN
                UPDATE SET 
                    source_identifier = ct.source_identifier, 
                    published_at = ct.published_at::timestamp, 
                    last_modified_at = ct.last_modified_at::timestamp, 
                    vulnerability_status = ct.vulnerability_status,
                    descriptions = ct.descriptions::jsonb,
                    metrics = ct.metrics::jsonb,
                    weaknesses = ct.weaknesses::jsonb,
                    configurations = ct.configurations::jsonb,
                    refs = ct.refs::jsonb
                WHEN NOT MATCHED THEN
                INSERT (
                    id,
                    source_identifier,
                    published_at,
                    last_modified_at,
                    vulnerability_status,
                    descriptions,
                    metrics,
                    weaknesses,
                    configurations,
                    refs
                )
                VALUES (
                    ct.id,
                    ct.source_identifier,
                    ct.published_at::timestamp,
                    ct.last_modified_at::timestamp,
                    ct.vulnerability_status,
                    ct.descriptions::jsonb,
                    ct.metrics::jsonb,
                    ct.weaknesses::jsonb,
                    ct.configurations::jsonb,
                    ct.refs::jsonb
                )
                """
            )

            self.conn.commit()
            print(f"Inserted cves batch ({len(cves)})")
        return cur.rowcount

    def merge_transformed_cves(self, transformed_cves: list):
        with self.conn.cursor() as cur:
            args_str = ",".join(
                cur.mogrify(
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        cve["id"],
                        cve["source_identifier"],
                        cve["published_at"],
                        cve["last_modified_at"],
                        cve["vulnerability_status"],
                        cve["description"],
                        json.dumps(
                            cve.get("weaknesses")
                            if cve.get("weaknesses") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve.get("configurations")
                            if cve.get("configurations") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve.get("refs") if cve.get("refs") not in (None, "") else []
                        ),
                        json.dumps(
                            cve.get("products")
                            if cve.get("products") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve.get("vendors")
                            if cve.get("vendors") not in (None, "")
                            else []
                        ),
                        json.dumps(
                            cve.get("types")
                            if cve.get("types") not in (None, "")
                            else []
                        ),
                    ),
                )
                for cve in transformed_cves
            )

            cur.execute(
                f"""
                WITH              
                cves_tmp AS (
                    SELECT * FROM (
                        VALUES
                            {args_str}
                        ) 
                        AS temporary_cte (
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
                        )
                )

                MERGE INTO cves
                USING cves_tmp
                ON cves.id = cves_tmp.id
                WHEN MATCHED THEN
                UPDATE SET 
                    source_identifier = cves_tmp.source_identifier, 
                    published_at = cves_tmp.published_at::timestamp, 
                    last_modified_at = cves_tmp.last_modified_at::timestamp, 
                    vulnerability_status = cves_tmp.vulnerability_status,
                    description = cves_tmp.description,
                    weaknesses = cves_tmp.weaknesses::jsonb,
                    configurations = cves_tmp.configurations::jsonb,
                    refs = cves_tmp.refs::jsonb,
                    products = cves_tmp.products::jsonb,
                    vendors = cves_tmp.vendors::jsonb,
                    types = cves_tmp.types::jsonb
                WHEN NOT MATCHED THEN
                INSERT (
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
                )
                VALUES (
                    cves_tmp.id,
                    cves_tmp.source_identifier,
                    cves_tmp.published_at::timestamp,
                    cves_tmp.last_modified_at::timestamp,
                    cves_tmp.vulnerability_status,
                    cves_tmp.description,
                    cves_tmp.weaknesses::jsonb,
                    cves_tmp.configurations::jsonb,
                    cves_tmp.refs::jsonb,
                    cves_tmp.products::jsonb,
                    cves_tmp.vendors::jsonb,
                    cves_tmp.types::jsonb
                )
                """
            )
        self.conn.commit()
        return cur.rowcount

    def get_raw_cves(self, start_index: int, limit: int):
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    source_identifier,
                    published_at,
                    last_modified_at,
                    vulnerability_status,
                    descriptions,
                    metrics,
                    weaknesses,
                    configurations,
                    refs             
                FROM cves_raw 
                ORDER BY id asc 
                OFFSET %s LIMIT %s
                """,
                (start_index, limit),
            )
            result = cur.fetchall()
            return self._map_raw_cves(result)

    def _map_raw_cves(self, raw_cves: List[Tuple]):
        cves = []
        for raw_cve in raw_cves:
            (
                id,
                source_identifier,
                published_at,
                last_modified_at,
                vulnerability_status,
                descriptions,
                metrics,
                weaknesses,
                configurations,
                refs,
            ) = raw_cve

            cves.append(
                {
                    "id": id,
                    "source_identifier": source_identifier,
                    "published_at": published_at,
                    "last_modified_at": last_modified_at,
                    "vulnerability_status": vulnerability_status,
                    "descriptions": descriptions,
                    "metrics": metrics,
                    "weaknesses": weaknesses,
                    "configurations": configurations,
                    "refs": refs,
                }
            )

        return cves

    def update_snapshot(self, year: int, sha256: str):
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snapshots (year, hash, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT(year)
                DO
                    UPDATE SET year = %s, hash = %s, updated_at = now()
            """,
                (year, sha256, year, sha256),
            )
            self.conn.commit()
            return cur.rowcount

    # def get_matchers(self, product: str) -> List[Dict]:
    #     with self.conn.cursor() as cur:
    #         cur.execute("""
    #             SELECT cve_id, year, hash, products, vendors, config, created_at
    #             FROM matchers
    #             WHERE products ? %s
    #             """, (product,))
    #         result = cur.fetchall()
    #         return self._map_matcher(result)

    # def _map_matcher(self, rows: List[Tuple]):
    #     matchers = []
    #     for (id, year, hash, products, vendors, config, created_at) in rows:
    #         matchers.append({
    #             "id": id,
    #             "year": year,
    #             "hash": hash,
    #             "products": products,
    #             "vendors": vendors,
    #             "config": config,
    #             "created_at": created_at
    #         })

    #     return matchers
