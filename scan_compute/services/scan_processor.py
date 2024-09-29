from __future__ import annotations
import asyncio
from dataclasses import dataclass
from datetime import datetime
import os
import traceback
from typing import Any, List, Dict, Optional, Tuple
import ujson
import boto3
from requests.structures import CaseInsensitiveDict

from botocore.exceptions import ClientError
from scan_compute.services.integrations.modules.module_processor import ModuleProcessor
from scan_compute.services.integrations.modules.pfunnel_processor import PFunnel
from scan_compute.services.integrations.resource_scorer import (
    ChecksProcessor,
    ResourceData,
)
from scan_compute.services.integrations.security_scorer import SecurityScorer
from scan_compute.services.scan_data_processor import ScanDataProcessor, ScanMetadata
from scan_compute.services.parsers.scan_report_parser import CSPMReport, Finding
from scan_compute.utils import enum
from scan_compute.utils.enum import (
    ScanStatus,
    ScanType,
)
from scan_compute.utils.cache import cache
from scan_compute.constants import cache_keys as ckeys, tables
from scan_compute.utils.logging import logger
from scan_compute.utils.config import settings
from scan_compute.utils.database import DB


class ProcessorError(Exception):
    """Custom exception class for Processor errors. Raising this error will fail the scan"""


@dataclass
class ScanDetails:
    status: ScanStatus
    compliant_count: int
    non_compliant_count: int
    non_evaluated_count: int
    total_count: int


class Processor:
    def __init__(
        self,
        file_path: str,
        schema_name: str,
        account_id: str,
        scan_id: str,
        scan_type: str,
        cloud_provider: str,
    ) -> None:
        self._file_path = file_path
        self._critical_exceptions: list[Exception] = []
        self._non_critical_exceptions: list[Exception] = []
        self._status: ScanStatus = ScanStatus.NOT_STARTED
        self._schema_name = schema_name
        self._account_id = account_id
        self._scan_id = scan_id
        self._cloud_provider = enum.CloudProvider.from_str(cloud_provider)

        self._applicable_compliances = []

        self._scan_type = ScanType.from_str(label=scan_type)
        self._logger = logger.bind(scan_id=scan_id, account_id=account_id)

        # NOTE: store the details to process security score
        self._scan_details: Optional[ScanDetails] = None

    async def run(self) -> None:
        """Run through the scan flow and handles errors."""
        self._status = ScanStatus.IN_PROGRESS
        try:
            await asyncio.gather(
                self._read_report_from_s3(),
                self._fetch_selected_compliance_packs(),
            )
            await self._process_report()
            if self.has_critical_errors:
                self._status = ScanStatus.FAILED
            else:
                self._status = ScanStatus.COMPLETED
        except ProcessorError as e:
            self._critical_exceptions.append(e)
            self._status = ScanStatus.FAILED
            self._logger.error(f"Critical error during scan: {e!s}")
        except Exception as e:
            traceback.print_exc()
            self._non_critical_exceptions.append(e)
            self._logger.warning(
                f"Unexpected error during scan: {e!s}",
            )
            self._status = ScanStatus.FAILED
        finally:
            self._logger.info(
                f"Scan [{self._scan_id}] completed with status: {self._status.value}",
            )

    async def _fetch_selected_compliance_packs(self) -> None:
        """fetches selected compliance packs"""
        if (
            (
                compliance_raw_data := await DB.fetch_data(
                    f"""
                        SELECT compliances
                        FROM {tables.SCAN_REPORT.format(schema_name=self._schema_name)}
                        WHERE scan_id = '{self._scan_id}'
                    """
                )
            )
            and compliance_raw_data
            and len(compliance_raw_data)
        ):
            try:
                self._applicable_compliances = [
                    item["compliance_version_case"]
                    for item in ujson.loads(compliance_raw_data[0]["compliances"])
                ]
            except (TypeError, ValueError, KeyError):
                raise ProcessorError(f"ISSUE WITH COMPLIANCES: {compliance_raw_data}")
        else:
            raise ProcessorError("COULDN'T FETCH COMPLIANCES")

    async def _read_report_from_s3(self) -> None:
        """downloads report from s3 and initializes"""
        try:
            key = f"report_for_scan_compute/{self._schema_name}/{self._account_id}/{self._scan_id}/raw_report.json"
            self._logger.info("trying to access: %s", key)
            s3_client = boto3.client(
                "s3",
                region_name=settings.S3_BUCKET_REGION_NAME,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
            data = s3_client.get_object(
                Bucket=settings.S3_BUCKET_NAME_FOR_SCAN_REPORT,
                Key=key,
            )

            raw_data = ujson.loads(data["Body"].read().decode("utf-8"))

            if self._scan_type == ScanType.MANUAL:
                self._scan_report = CSPMReport(**raw_data)
                self._logger.debug("SCAN REPORT READING FROM S3 DONE")
                cache.set(
                    ckeys.FULL_RAW_REPORT.format(account_id=self._account_id), raw_data
                )
                self._logger.info("CACHED FULL RAW SCAN REPORT")
            else:
                await self._append_last_cached_report(raw_data)

        except (ClientError, ujson.JSONDecodeError) as e:
            self._critical_exceptions.append(e)
            raise ProcessorError(
                f"WHILE FETCHING FILE FROM S3: {e!s}",
            )

    async def _append_last_cached_report(self, current_report: Dict[str, Any]) -> None:
        """appends last cached report for RTM scans"""
        last_report = (
            cache.get(ckeys.FULL_RAW_REPORT.format(account_id=self._account_id)) or {}
        )
        if not last_report:
            raise ProcessorError(
                "RTM CANNOT BE RUN WITHOUT A FULL MANUAL SCAN IN PLACE"
            )

        # delete the services from the last cached report that is present in the current report
        for service in current_report["service_list"]:
            last_report["services"].pop(service)

        for service in last_report["services"].keys():
            self._logger.debug("FORWARDED %s FROM LAST CACHED REPORT", service)
            current_report["services"][service] = last_report["services"][service]

            # also update the service list of the current report
            if service not in current_report["service_list"]:
                current_report["service_list"].append(service)

        self._scan_report = CSPMReport(**current_report)
        self._logger.debug("CARRY-FORWARDED SERVICES")
        cache.set(
            ckeys.FULL_RAW_REPORT.format(account_id=self._account_id), current_report
        )

        self._logger.info("CACHED FULL RAW SCAN REPORT")

    async def _read_report_from_file_to_memory(self) -> None:
        """Reads self._file_path and stores it in self._scan_report"""
        if not os.path.exists(self._file_path):
            raise ProcessorError(
                f"File does not exist: {self._file_path}",
            )
        try:
            with open(self._file_path) as f:
                # NOTE: probably this does not make a lot of sense here
                # NOTE: integrate identity using an API call to get the processed findings
                raw_report = ujson.load(f)
                self._scan_report = CSPMReport(**raw_report)

            self._logger.debug("SCAN REPORT READING FROM FILE DONE")
            cache.set(
                ckeys.FULL_RAW_REPORT.format(account_id=self._account_id), raw_report
            )
            self._logger.info("CACHED FULL RAW SCAN REPORT")

        except (OSError, ujson.JSONDecodeError) as e:
            self._critical_exceptions.append(e)
            raise ProcessorError(
                f"Error reading or parsing file: {e!s}",
            )

    def _process_path(self, path: str) -> None:
        """Process a single JSON path."""
        try:
            cache_value = cache.get(
                ckeys.DISPLAY_PATH_TO_RESOURCE.format(
                    account_id=self._account_id, display_path=path
                )
            )
            if cache_value is None:
                value = self._scan_report.services
                for key in path.split("."):
                    if key.isdigit():
                        value = value[int(key)]  # type: ignore
                    else:
                        value = value[key]  # type: ignore

                value = cache.set(
                    ckeys.DISPLAY_PATH_TO_RESOURCE.format(
                        account_id=self._account_id, display_path=path
                    ),
                    value,
                )

        except (KeyError, IndexError) as e:
            self._logger.error(f"PATH: {path} FAILED DUE TO {e}")

    def __process_regions_from_display_path_item(self, display_path: str) -> List[str]:
        """parses region from display path, if not found returns global"""
        if "regions" in display_path:
            region_split = display_path.split("regions")[-1]
            return [region_split.split(".")[1]]

        # TODO: add one more condition to check from resource config,
        # before actually returning global region
        # but since this is used in _process_resource_report and _process_rules_report
        # we need to be careful before introducing the dependency
        return ["global"]

    def __get_control_evaluation(
        self, control_findings: Dict[str, List[Finding]]
    ) -> str:
        """control is compliant only if all applicable rules are compliant"""
        if len(control_findings["non-compliant"]):
            return "non-compliant"
        elif len(control_findings["compliant"]):
            return "compliant"
        else:
            return "not-applicable"

    def __get_resource_name_and_tags_from_config(
        self, config: Dict[str, Any]
    ) -> Tuple[str, Any]:
        """tries to extract resource name and resource tags from resource configuration"""
        in_config = CaseInsensitiveDict(config)
        return in_config.get("name", ""), in_config.get("tags", [])

    def __get_classification_and_production_from_tags(
        self, tags: Any
    ) -> Tuple[str, str]:
        """checks for tag to make it prod critical resource"""
        classification, production = "", ""
        if isinstance(tags, list):
            for dic in tags:
                if dic["Key"] == "classification" or dic["Key"] == "Classification":
                    classification = "Critical"
                if dic["Key"] == "production" or dic["Key"] == "Production":
                    production = "True"
        return classification, production

    def __check_public_resource(self, item: str, resource_type: str) -> bool:
        """checks isPublic key in resource configuration or internet exposed rules"""
        if config := cache.get(
            ckeys.DISPLAY_PATH_TO_RESOURCE.format(
                account_id=self._scan_report.account_id, display_path=item
            )
        ):
            if config.get("isPublic") is True:
                return True

        internet_exposed_rules = (
            cache.get(
                ckeys.INTERNET_EXPOSED_RULES_FOR.format(resource_type=resource_type)
            )
            or []
        )
        for rule in self._scan_report._item_to_failed_rule.get(item) or []:
            if (
                rule.master_rule_id in internet_exposed_rules  # type: ignore
                and rule.evaluation == "non-compliant"
            ):
                return True

        return False

    def __get_highest_severity_from_list_of_findings(
        self,
        findings: Dict[str, List[Finding]],
    ) -> str:
        """returns highest severity from the list of findings"""
        severity_map = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "WARNING": 3,
        }

        all_findings = [
            finding for findings_list in findings.values() for finding in findings_list
        ]

        if not all_findings:
            return "UNKNOWN"

        all_findings.sort(
            key=lambda f: severity_map.get(f.severity.upper(), float("inf"))
            if f.severity
            else float("inf")
        )
        return all_findings[0].severity

    async def _process_resource_report(self) -> None:
        """processes resource compliance from findings report"""

        resource_report = []
        account_details = (
            cache.get(ckeys.ACCOUNT_DETAILS.format(account_id=self._account_id)) or {}
        )
        for item in self._scan_report.all_items:
            regions = self.__process_regions_from_display_path_item(item)
            res_config = (
                cache.get(
                    ckeys.DISPLAY_PATH_TO_RESOURCE.format(
                        account_id=self._scan_report.account_id, display_path=item
                    )
                )
                or {}
            )

            res_name, tags = self.__get_resource_name_and_tags_from_config(res_config)
            res_type = self._scan_report.get_item_to_resource_type(item)
            res_category_mapping = (
                cache.get(ckeys.SERVICE_AND_CATEGORY_FOR.format(resource_type=res_type))
                or {}
            )
            classification, production = (
                self.__get_classification_and_production_from_tags(tags)
            )
            evaluation = (
                "non-compliant"
                if item in self._scan_report._item_to_failed_rule
                else "compliant"
            )
            applicable_rules = [
                {
                    "master_rule_id": item.master_rule_id,
                    "resource_type": item.affected_resource_type,
                    "severity": item.severity,
                    "rule_name": item.rule_name,
                    "risk_category": item.risk_category,
                    "evaluation": item.evaluation,
                }
                for item in (
                    self._scan_report._resource_type_to_findings.get(res_type) or []
                )
            ]

            temp_comp = [
                cache.get(
                    ckeys.RULE_TO_COMPLIANCE.format(
                        master_rule_id=rule["master_rule_id"]
                    )
                )
                or {}
                for rule in applicable_rules
            ]
            applicable_compliances = list(
                set(
                    [
                        c[1]
                        for item in temp_comp
                        for c in item.get("compliance_info", [])  # type: ignore
                    ]
                )
            )

            row = {
                "environment_id": self._account_id,
                "environment_name": account_details.get(
                    "environment_name", "NO_ENV_NAME"
                ),
                "environment_tags": account_details.get("environment_tags", []),
                "account_id": self._account_id,
                "scan_id": self._scan_id,
                "cloud_provider": self._scan_report.provider_code,
                "evaluation": evaluation,
                "applicable_rules": applicable_rules,
                "applicable_compliances": applicable_compliances,
                "resource_id": item.split(".")[-1],
                "resource_type": res_type,
                "service": res_category_mapping.get("service", "NO SERVICE"),
                "service_category": res_category_mapping.get(
                    "service_category", "NO SERVICE CATEGORY"
                ),
                "resource_name": res_name,
                "tags": tags,
                "regions": regions,
                "region": regions,
                "severity": "-"
                if evaluation != "non-compliant"
                else self.__get_highest_severity_from_list_of_findings(
                    {"findings": self._scan_report._item_to_failed_rule.get(item) or []}
                ),
                "resource_configuration": res_config,
                "violations": len(
                    self._scan_report._item_to_failed_rule.get(item) or []
                ),
                "classification": classification,
                "production": production,
                "is_public": self.__check_public_resource(item, res_type),
                "attack_path_labels": [],
                "risk": list(
                    set(
                        [
                            risk
                            for finding in self._scan_report._item_to_failed_rule[item]
                            for risk in finding.risk_category
                        ]
                        if item in self._scan_report._item_to_failed_rule
                        else []
                    )
                ),
                "last_updated": datetime.now().strftime("%Y-%m-%d , %H:%M:%S"),
            }

            if row["evaluation"] == "non-compliant":
                row["shield_severity"] = ChecksProcessor.process_checks(
                    ResourceData(**row)
                )
            else:
                row["shield_severity"] = "-"

            resource_report.append(row)
            cache.set(
                ckeys.RES_DETAILS.format(
                    account_id=self._scan_report.account_id,
                    display_path=item,
                ),
                {
                    "resource_id": row["resource_id"],
                    "resource_type": row["resource_type"],
                    "evaluation": row["evaluation"],
                    "resource_name": row["resource_name"],
                    "region": row["regions"],
                    "tags": row["tags"],
                },
            )

        cache.set(
            ckeys.RESOURCE_REPORT.format(account_id=self._scan_report.account_id),
            resource_report,
        )

        with open(
            os.getcwd()
            + f"/scan_compute/reports/{self._cloud_provider.value}_resource_report.json",
            "w+",
        ) as f:
            ujson.dump({"resources": resource_report}, f)

        compliant_resources = sum(
            item["evaluation"] == "compliant" for item in resource_report
        )
        non_compliant_resources = sum(
            item["evaluation"] == "non-compliant" for item in resource_report
        )
        self._logger.info(
            "%d RES COMPLIANT and %d RES NON-COMPLIANT",
            compliant_resources,
            non_compliant_resources,
        )
        self._logger.info(
            "RESOURCE REPORT STORED: scan_compute/reports/resource_report.json"
        )

    async def _process_rules_report(self) -> None:
        """processes rule compliance from findings report"""
        rules_report = []

        if environment_name := cache.get(
            ckeys.ACCOUNT_DETAILS.format(account_id=self._scan_report.account_id)
        ):
            environment_name = environment_name["environment_name"]  # type: ignore
        else:
            environment_name = "NO ENVIRONMENT NAME"

        for rule in self._scan_report.service_findings:
            if rule_description := cache.get(
                ckeys.RULE_METADATA.format(master_rule_id=rule.master_rule_id)
            ):
                rule_description = rule_description["description"]  # type: ignore
            else:
                rule_description = "NO RULE DESCRIPTION"

            if applicable_compliances := cache.get(
                ckeys.RULE_TO_COMPLIANCE.format(master_rule_id=rule.master_rule_id)
            ):
                applicable_compliances = list(
                    set(
                        [
                            item[1]
                            for item in applicable_compliances["compliance_info"]  # type: ignore
                        ]
                    )
                )
            else:
                applicable_compliances = []

            applicable_regions = list(
                set(
                    [
                        r
                        for item in self._scan_report._resource_type_to_findings[
                            rule.affected_resource_type
                        ]
                        for i in item.items
                        for r in self.__process_regions_from_display_path_item(i)
                    ]
                )
            )

            rules_report.append(
                {
                    "environment_name": "TEST_ENV",
                    "account_id": self._account_id,
                    "cloud_provider": self._scan_report.provider_code,
                    "scan_id": self._scan_id,
                    "master_rule_id": rule.master_rule_id,
                    "service": rule.service,
                    "rule_description": rule_description,
                    "severity": rule.severity,
                    "evaluation": rule.evaluation,
                    "affected_resources": rule.checked_items,
                    "resource_type": rule.affected_resource_type,
                    "resources_breakup": {
                        "failed": rule.flagged_items,
                        "passed": len(
                            self._scan_report._display_path_to_items[rule.display_path]
                        )
                        - rule.flagged_items,
                        "non_evaluated": 0,
                    },
                    "compliance_family": applicable_compliances,
                    "applicable_regions": applicable_regions,
                    "risk_category_new": rule.risk_category,
                    "risk_category": rule.risk_category,
                    "last_updated": datetime.now().__str__(),
                    "risk_expansion_data": [
                        cache.get(
                            ckeys.RES_DETAILS.format(
                                account_id=self._scan_report.account_id,
                                display_path=item,
                            )
                        )
                        or {}
                        for item in self._scan_report._resource_type_to_items.get(
                            rule.affected_resource_type, []
                        )
                    ],
                },
            )

        cache.set(
            ckeys.RULES_REPORT.format(account_id=self._scan_report.account_id),
            rules_report,
        )

        with open(
            os.getcwd()
            + f"/scan_compute/reports/{self._cloud_provider.value}_rules_report.json",
            "w+",
        ) as f:
            ujson.dump({"rules": rules_report}, f)

        self._logger.info("RULE REPORT STORED: scan_compute/reports/rules_report.json")

    async def _process_control_report(self) -> None:
        """process compliance report from finfings report"""

        def __get_resource_count_from_all_applicable_rules(
            findings: Dict[str, List[Finding]],
        ) -> Tuple[int, int]:
            """returns a breakup of failed and passed resources count for a control"""
            all_findings = [
                finding
                for findings_list in findings.values()
                for finding in findings_list
            ]
            failed_items, all_items = set(), set()
            for rule in all_findings:
                all_items.update(
                    self._scan_report._display_path_to_items[rule.display_path]
                )
                failed_items.update(rule.items)

            return len(failed_items), len(all_items - failed_items)

        control_report = []
        temp_control_findings: Dict[str, Dict[str, List[Finding]]] = {}
        for finding in self._scan_report.service_findings:
            if applicable_controls := cache.get(
                ckeys.RULE_TO_COMPLIANCE.format(master_rule_id=finding.master_rule_id)
            ):
                applicable_controls = applicable_controls["compliance_info"]  # type: ignore
                for control, compliance in applicable_controls:  # type: ignore
                    if compliance in self._applicable_compliances:
                        if control not in temp_control_findings:
                            temp_control_findings[control] = {
                                "compliant": [],
                                "non-compliant": [],
                                "not-applicable": [],
                            }

                        temp_control_findings[control][finding.evaluation].append(
                            finding
                        )
            else:
                self._logger.warning(
                    "[%s] DOES NOT HAVE ANY APPLICABLE CONTROLS", finding.master_rule_id
                )

        for control, control_findings in temp_control_findings.items():
            if control_metadata := (
                cache.get(ckeys.CONTROL_METADATA.format(control=control)) or {}
            ):
                ...
            else:
                self._logger.bind(control_id=control).warning(
                    "SKIPPING DUE TO NO METADATA"
                )
                continue

            failed, passed = __get_resource_count_from_all_applicable_rules(
                control_findings
            )
            control_report.append(
                {
                    "environment_name": "TEST_ENV",
                    "account_id": self._scan_report.account_id,
                    "scan_id": self._scan_id,
                    "control": control,
                    "control_description": control_metadata["control_description"],
                    "evaluation": self.__get_control_evaluation(control_findings),
                    "severity": self.__get_highest_severity_from_list_of_findings(
                        control_findings
                    ),
                    "compliance": control_metadata["compliance"],
                    "rule_expansion_data": {
                        "rule_pass": len(control_findings["compliant"]),
                        "rule_fail": len(control_findings["non-compliant"]),
                        "resource_pass": passed,
                        "resource_fail": failed,
                    },
                    "rule_count": len(control_findings["compliant"])
                    + len(control_findings["non-compliant"]),
                    "resources_count": passed + failed,
                }
            )

        cache.set(
            ckeys.CONTROL_REPORT.format(account_id=self._scan_report.account_id),
            control_report,
        )

        with open(
            os.getcwd()
            + f"/scan_compute/reports/{self._cloud_provider.value}_control_report.json",
            "w+",
        ) as f:
            ujson.dump({"controls": control_report}, f)

        self._logger.info(
            "CONTROL REPORT STORED: scan_compute/reports/control_report.json"
        )

    async def _process_report(self) -> None:
        """Process the report and handle any exceptions"""
        try:
            module_findings = await ModuleProcessor.process_modules(
                self._cloud_provider,
                self._account_id,
                self._scan_id,
                self._scan_report.services,
            )
            self._scan_report.process_module_findings(module_findings)

            # NOTE: resource processing is done first to cache the item metadata required
            await self._process_resource_report()
            await asyncio.gather(
                self._process_rules_report(),
                self._process_control_report(),
            )

            if await ScanDataProcessor.insert_reports_to_db(
                ScanMetadata(
                    account_id=self._scan_report.account_id,
                    scan_id=self._scan_id,
                    schema_name=self._schema_name,
                )
            ):
                self._logger.info("ALL SCAN DATA INSERTED")
            else:
                self._logger.warning("COULD NOT INSERT DATA TO DB")

            await PFunnel.insert_pfunnel_data_to_mongo(
                self._schema_name,
                self._scan_id,
                self._account_id,
            )

            # Visualizer trigger - should triggered at last or after the
            # resource details are stored in table

            # TODO: we also need to populate trend cache and inventory dynamic columns cache
            # HACK: for now let's have a cache subscriber for updating cache in backend

        except ProcessorError as e:
            self._logger.error(e)
            self._critical_exceptions.append(e)
            raise ProcessorError(
                f"ERROR during report processing: {e!s}",
            )

    def get_status(self) -> dict[str, Any]:
        """Return the status of the scan."""
        return {
            "status": self._status.value,
            "errors": [str(e) for e in self._critical_exceptions],
            "exceptions": [str(e) for e in self._non_critical_exceptions],
        }

    async def _fail_scan(self):
        """fails the current scan in tClient_Scan_Report"""
        await DB.execute_query(f"""
            UPDATE {tables.SCAN_REPORT.format(schema_name=self._schema_name)}
            SET
                scan_status='fail'
            WHERE
                scan_id='{self._scan_id}'
        """)

    async def _complete_scan(self):
        """marks the scan as complete and updates its scan_end, security score and evaluation"""
        scan_end = datetime.now().strftime("%Y-%m-%d , %H:%M:%S")
        security_score = await SecurityScorer.get_security_score(
            self._schema_name, self._scan_id
        )
        self._logger.info(f"SECURITY SCORE: {security_score}")

        await DB.execute_query(f"""
            UPDATE {tables.SCAN_REPORT.format(schema_name=self._schema_name)}
            SET
                scan_status='complete',
                security_score='{security_score}',
                scan_end='{scan_end}'
            WHERE
                scan_id='{self._scan_id}'
        """)

    async def update_scan_data(self) -> None:
        """calculates security score if scan completed successfully and updates in pg"""
        if self.has_critical_errors:
            self._logger.info("MAKING SCAN FAIL")
            await self._fail_scan()
        else:
            self._logger.info("MAKING SCAN COMPLETE")
            await self._complete_scan()

    @property
    def has_critical_errors(self) -> bool:
        """Check if there are any critical errors."""
        return len(self._critical_exceptions) > 0
