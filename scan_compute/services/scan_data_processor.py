from __future__ import annotations

from dataclasses import dataclass
from asyncpg.pool import PoolConnectionProxy

import scan_compute.constants.tables as T
from scan_compute.utils.cache import cache
import scan_compute.constants.cache_keys as ckeys
from scan_compute.utils.database import DB, MongoDB
from scan_compute.utils.logging import logger


@dataclass
class ScanMetadata:
    schema_name: str
    account_id: str
    scan_id: str


class ScanDataProcessor:
    _logger = logger.bind(name="Scan Data Processor")

    @classmethod
    async def insert_reports_to_db(cls, scan_metadata: ScanMetadata) -> bool:
        pool = await DB.get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                try:
                    # NOTE: i tried with asyncio.gather but we cannot share a conn between coroutines
                    await cls._store_resource_report(scan_metadata, conn)
                    await cls._store_rules_report(scan_metadata, conn)
                    await cls._store_control_report(scan_metadata, conn)
                    cls._store_resource_config_in_mongo(scan_metadata)
                    return True
                except Exception as e:
                    cls._logger.bind(error=e).error("while inserting data")
                    return False

    @classmethod
    def _store_resource_config_in_mongo(cls, scan_metadata: ScanMetadata):
        """reads resource report from cache and inserts config along with some metadata to mongo"""
        if resource_report := cache.get(
            ckeys.RESOURCE_REPORT.format(account_id=scan_metadata.account_id)
        ):
            cls._logger.info("NOW INSERTING CONFIG TO MONGO ...")
            resource_inserted = MongoDB.bulk_insert(
                scan_metadata.schema_name,
                "resource_details",
                [
                    {
                        "resource_configuration": item["resource_configuration"],
                        "scan_id": item["scan_id"],
                        "account_id": item["account_id"],
                        "resource_id": item["resource_id"],
                        "resource_type": item["resource_type"],
                        "regions": item["regions"],
                    }
                    for item in resource_report
                ],
            )
            if not resource_inserted:
                cls._logger.info(
                    f"FAILED TO INSERT {len(resource_report)} DOCS IN MONGO"
                )

        else:
            cls._logger.bind(account_id=scan_metadata.account_id).error(
                "NO RESOURCE REPORT FOUND IN CACHE"
            )

    @classmethod
    async def _store_resource_report(
        cls, scan_metadata: ScanMetadata, conn: PoolConnectionProxy
    ):
        """reads resource report from cache and inserts data to PG as part of a transaction"""
        if resource_report := cache.get(
            ckeys.RESOURCE_REPORT.format(account_id=scan_metadata.account_id)
        ):
            cls._logger.info(
                f"{type(resource_report)} {len(resource_report)} RESOURCE REPORT"
            )
            resource_inserted = await DB.bulk_insert(
                T.RESOURCE_TABLE.format(schema_name=scan_metadata.schema_name),
                resource_report,
                conn,
            )
            if not resource_inserted:
                cls._logger.info(f"FAILED TO INSERT {len(resource_report)} RULES")

        else:
            cls._logger.bind(account_id=scan_metadata.account_id).error(
                "NO RULES REPORT FOUND IN CACHE"
            )

    @classmethod
    async def _store_rules_report(
        cls, scan_metadata: ScanMetadata, conn: PoolConnectionProxy
    ):
        """reads rules report from cache and inserts it to db"""
        if rules_report := cache.get(
            ckeys.RULES_REPORT.format(account_id=scan_metadata.account_id)
        ):
            cls._logger.info(f"{type(rules_report)} {len(rules_report)} RULES REPORT")
            rules_inserted = await DB.bulk_insert(
                T.RULE_EXPANSION.format(schema_name=scan_metadata.schema_name),
                rules_report,
                conn,
            )
            if not rules_inserted:
                cls._logger.info(f"FAILED TO INSERT {len(rules_report)} RULES")

        else:
            cls._logger.bind(account_id=scan_metadata.account_id).error(
                "NO RULES REPORT FOUND IN CACHE"
            )

    @classmethod
    async def _store_control_report(
        cls, scan_metadata: ScanMetadata, conn: PoolConnectionProxy
    ):
        """reads control report from cache and inserts it to db"""

        if control_report := cache.get(
            ckeys.CONTROL_REPORT.format(account_id=scan_metadata.account_id)
        ):
            cls._logger.info(
                f"{type(control_report)} {len(control_report)} CONTROL REPORT"
            )
            control_inserted = await DB.bulk_insert(
                T.CONTROL_TABLE.format(schema_name=scan_metadata.schema_name),
                control_report,
                conn,
            )
            if not control_inserted:
                cls._logger.info(f"FAILED TO INSERT {len(control_report)} CONTROLS")
        else:
            cls._logger.bind(account_id=scan_metadata.account_id).error(
                "NO CONTROL REPORT FOUND IN CACHE"
            )
