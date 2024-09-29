from structlog.typing import ExceptionTransformer
import ujson
from typing import List, Tuple
from scan_compute.utils.cache import cache
from scan_compute.utils.database import DB
from scan_compute.constants import tables, cache_keys as ckeys
from scan_compute.utils.logging import logger
import asyncio
import os

clog = logger.bind(name="Cache Updation")


class PopulateCache:
    async def get_all_schemas(self) -> List[str]:
        """fetches all schemas in the db"""
        if raw_data := await DB.fetch_data(
            "SELECT schema_name FROM information_schema.schemata"
        ):
            return [
                item["schema_name"]
                for item in raw_data
                if item["schema_name"].endswith("root")
            ]

        return []

    async def rule_to_compliance_mapping_from_db(self, schema_name: str = "cps_root"):
        return await DB.fetch_data(f"""
            SELECT
                MASTERID,
                DESCRIPTION,
                AFFECTEDRESOURCETYPE,
                ASSOCIATEDCOMPLIANCECONTROLS,
                MITRE_TECHNIQUE_ID
            FROM
                {tables.RULES_DATABASE.format(schema_name=schema_name)}
        """)

    async def get_rule_metadata(self, schema_name: str = "cps_root"):
        return await DB.fetch_data(f"""
            SELECT
                *
            FROM
                {tables.RULES_DATABASE.format(schema_name=schema_name)}
        """)

    async def get_account_metadata(self, schema_name: str = "cps_root"):
        return await DB.fetch_data(f"""
            SELECT
                *
            FROM
                {tables.ACCOUNT.format(schema_name=schema_name)}
        """)

    async def get_service_resource_and_category_mapping(self):
        return await DB.fetch_data(f"""
            SELECT
                resource_type, service, service_category
            FROM
                {tables.SERVICE_CATEGORY_MAPPING}
        """)

    async def get_internet_exposed_res_type_to_rules_mapping(
        self, schema_name: str = "cps_root"
    ):
        return await DB.fetch_data(f"""
            SELECT
                affectedresourcetype as resource_type,
                ARRAY_AGG(masterid) as rule_ids
            FROM
                {tables.RULES_DATABASE.format(schema_name=schema_name)}
            WHERE 
                rule_category = 'Internet exposed'
            GROUP BY affectedresourcetype;
        """)

    async def get_control_metadata(self):
        return await DB.fetch_data(f"""
            SELECT
                *
            FROM
                {tables.COMPLIANCE_CONTROL}
        """)

    async def _populate_rule_compliance_cache(self, schema_name: str = "cps_root"):
        clog.info("RUNNING _populate_rule_compliance_cache")

        processed_data = []
        temp_mapping = {}

        if raw_data := await self.rule_to_compliance_mapping_from_db(schema_name):
            for item in raw_data:
                try:
                    data = ujson.loads(
                        ujson.loads(item["associatedcompliancecontrols"])
                    )
                except ujson.JSONDecodeError as e:
                    clog.error("error while reading compliance info %s", e)
                    continue

                controls_and_compliance = [
                    (control.strip(), i["compliance"])
                    for i in data["associatedComplianceControl"]
                    for control in i["name"].split(",")
                ]
                applicable_controls = [
                    (c, i[1]) for i in controls_and_compliance for c in i[0].split("\n")
                ]

                p_datum = {
                    "description": item["description"],
                    "affected_resource_type": item["affectedresourcetype"],
                    "mitre_technique_ids": item["mitre_technique_id"],
                    "compliance_info": applicable_controls,
                }
                processed_data.append(p_datum)

                cache.set(
                    ckeys.RULE_TO_COMPLIANCE.format(master_rule_id=item["masterid"]),
                    p_datum,
                )

                for control, _ in applicable_controls:
                    if control in temp_mapping:
                        temp_mapping[control].append(item["masterid"])
                    else:
                        temp_mapping[control] = [item["masterid"]]

            for control in temp_mapping:
                cache.set(
                    ckeys.CONTROL_TO_RULE.format(control_id=control),
                    temp_mapping[control],
                )
        else:
            clog.bind(schema_name=schema_name).warning("NO DATA FOR RULE TO COMPLIANCE")

        clog.debug("PROCESSED %d RULES", len(raw_data))
        clog.debug("PROCESSED %d CONTROLS", len(list(temp_mapping.keys())))

    async def _populate_rule_metadata(self, schema_name: str = "cps_root"):
        clog.info("RUNNING _populate_rule_metadata")
        if rule_metadata := await self.get_rule_metadata():
            for item in rule_metadata:
                cache.set(
                    ckeys.RULE_METADATA.format(master_rule_id=item["masterid"]),
                    item,
                )
        else:
            clog.bind(schema_name=schema_name).warning("NO DATA FOR RULE METADATA")

    async def _populate_account_metadata(self, schema_name: str = "cps_root"):
        clog.info("RUNNING _populate_account_metadata")
        if raw_data := await self.get_account_metadata(schema_name):
            for item in raw_data:
                cache.set(
                    ckeys.ACCOUNT_DETAILS.format(account_id=item["account_id"]),
                    item,
                )
        else:
            clog.bind(schema_name=schema_name).warning("NO DATA FOR ACCOUNTS")

    async def _populate_control_metadata(self):
        clog.info("RUNNING _populate_control_metadata")
        if raw_data := await self.get_control_metadata():
            for item in raw_data:
                cache.set(
                    ckeys.CONTROL_METADATA.format(control=item["control_id"]),
                    item,
                )
        else:
            clog.warning("NO DATA FOR CONTROL METADATA")

    async def _populate_category_mapping(self):
        clog.info("RUNNING _populate_category_mapping")
        if raw_data := await self.get_service_resource_and_category_mapping():
            for item in raw_data:
                cache.set(
                    ckeys.SERVICE_AND_CATEGORY_FOR.format(
                        resource_type=item["resource_type"]
                    ),
                    item,
                )
        else:
            clog.warning("NO DATA FOR RESOURCE, SERVICE AND CATEGORY MAPPING")

    async def _populate_internet_exposed_types(self, schema_name: str = "cps_root"):
        clog.info("RUNNING _populate_internet_exposed_types")
        if raw_data := await self.get_internet_exposed_res_type_to_rules_mapping(
            schema_name
        ):
            for item in raw_data:
                cache.set(
                    ckeys.INTERNET_EXPOSED_RULES_FOR.format(
                        resource_type=item["resource_type"]
                    ),
                    item["rule_ids"],
                )
        else:
            clog.warning("NO DATA FOR INTERNET EXPOSED RULES")

    async def _populate_schema_to_account_mapping(self):
        clog.info("RUNNING _populate_schema_to_account_mapping")
        if raw_data := await self.get_all_schemas():
            for item in raw_data:
                if accounts := await DB.fetch_data(
                    f"SELECT account_id FROM {tables.ACCOUNT.format(schema_name = item)}"
                ):
                    cache.set(
                        ckeys.SCHEMA_TO_ACCOUNTS.format(
                            schema_name=item,
                        ),
                        [item["account_id"] for item in accounts],
                    )
                    for account in accounts:
                        cache.set(
                            ckeys.ACCOUNT_TO_SCHEMA.format(
                                account_id=account["account_id"],
                            ),
                            item,
                        )

        else:
            clog.warning("NO DATA FOR SCHEMA TO ACCOUNT ID INFO")

    async def _populate_anomaly_threat_rule_file_cache(self):
        clog.info("RUNNING _populate_anomaly_threat_rule_file_cache")
        anomaly_threat_rules_path = os.path.join(
            os.getcwd(), "scan_compute", "constants", "anomaly_threat_rules"
        )
        all_rule_file_names: List[Tuple[str, str]] = []
        for _, _, files in os.walk(anomaly_threat_rules_path):
            for file in files:
                clog.debug(f"PROCESSING FILE: {file}")
                all_rule_file_names.append(
                    (anomaly_threat_rules_path + "/" + file, file.split(".")[0])
                )

            break

        for path, file_name in all_rule_file_names:
            try:
                with open(path, "r") as f:
                    rule_data = ujson.load(f)
            except ujson.JSONDecodeError:
                clog.bind(file=path, name=file_name).warning("SKIPPING")
                continue

            cache.set(
                ckeys.ANOMALY_THREAT_RULE_FILE_CACHE.format(
                    rule_file_name_without_suffix=file_name
                ),
                rule_data,
            )

    async def run(self):
        clog.info("STARTING CACHE POPULATION")
        await asyncio.gather(
            self._populate_rule_compliance_cache(),
            self._populate_rule_metadata(),
            self._populate_account_metadata(),
            self._populate_control_metadata(),
            self._populate_category_mapping(),
            self._populate_internet_exposed_types(),
            self._populate_schema_to_account_mapping(),
            self._populate_anomaly_threat_rule_file_cache(),
        )
        clog.info("POPULATE CACHE DONE")


if __name__ == "__main__":
    asyncio.run(PopulateCache().run())
