import asyncio
import traceback
from typing import Any, Dict, List, Tuple
import ujson


from scan_compute.constants.tables import (
    RESOURCE_TABLE,
    RULE_EXPANSION,
    RULES_DATABASE,
    VULNERABILITY,
)
from scan_compute.utils.logging import logger
from scan_compute.utils.cache import cache
from scan_compute.utils.database import DB, MongoDB


slog = logger.bind(name="Pfunnel Processor")


class PFunnel:
    pf_obj = None

    @classmethod
    async def run(
        cls,
        schema_name: str,
        scan_id: str,
        environment_id: str,
        cloud_provider: str = "aws",
    ):
        if cls.pf_obj:
            return await cls.pf_obj._run(
                schema_name, scan_id, environment_id, cloud_provider
            )
        else:
            cls.pf_obj = PFunnel()
            return await cls.pf_obj._run(
                schema_name, scan_id, environment_id, cloud_provider
            )

    async def get_risk_to_rule_mapping(self, schema_name: str) -> Dict[str, List[str]]:
        rules_db = RULES_DATABASE.format(schema_name=schema_name)
        raw_data = await DB.fetch_data(
            f"""
                SELECT risk_category->>'risk_category_primary' as risk, array_agg(masterid) as rule_ids
                FROM {rules_db}
                GROUP BY risk_category->>'risk_category_primary';
            """
        )
        mapping = {}
        for item in raw_data:
            mapping[item["risk"]] = item["rule_ids"]
        return mapping

    async def get_risks_count_for_each_rule_category(
        self,
        schema_name: str,
        latest_scan_ids: List[str],
    ) -> Dict[str, int]:
        rule_expansion = RULE_EXPANSION.format(
            schema_name=schema_name,
        )
        if len(latest_scan_ids) == 1:
            latest_scan_ids.append("0")
        result = {}
        rule_mapping = await self.get_risk_to_rule_mapping(schema_name)
        for rule_cat, rule_ids in rule_mapping.items():
            # count of failing resources for the given risk
            raw_data = await DB.fetch_data(
                f"""
                SELECT SUM((resources_breakup->>'failed')::int) as count
                FROM {rule_expansion}
                WHERE 
                    master_rule_id IN {tuple(rule_ids)} 
                    AND scan_id in {tuple(latest_scan_ids)}
            """,
            )
            if raw_data and len(raw_data):
                result[rule_cat] = raw_data[0]["count"] or 0

        return result

    async def get_count_of_public_lambda_with_risky_role(
        self,
        schema_name: str,
        latest_scan_ids: List[str],
    ) -> List[List]:
        check1 = False
        lambda_check1 = []
        identity_check1 = []

        relations: list[list[Any]] = []

        noSql_client = MongoDB._client
        client_db = noSql_client[f"shield_{schema_name}"]

        """ get role_arn from config for public lambda resource"""
        results = list(
            client_db["resource_details"].find(
                {
                    "$and": [
                        {
                            "scan_id": {
                                "$in": latest_scan_ids,
                            },
                            "resource_type": {
                                "$in": ["AWS.Lambda.Function"],
                            },
                        },
                    ],
                },
                {
                    "_id": 0,
                    "role_arn": "$resource_configuration.role_arn",
                    "is_public": "$resource_configuration.isPublic",
                    "resource_id": 1,
                    "regions": 1,
                },
            ),
        )
        public_lambdas = [item for item in results if item.get("is_public")]
        if public_lambdas:
            public_lambda_ids = [item["resource_id"] for item in public_lambdas]
            if len(public_lambda_ids) == 1:
                public_lambda_ids.append("0")

            """ get IAM roles attached to public lambdas"""
            for item in public_lambdas:
                role_name = item["role_arn"].split("/")[-1]
                # check if admin risk is attached to this role
                res: list[dict[str, str]] = list(
                    client_db["identity_roles"].find(
                        {
                            "$and": [
                                {
                                    "scan_id": {
                                        "$in": latest_scan_ids,
                                    },
                                    "data.name": {"$eq": role_name},
                                },
                            ],
                        },
                        {"_id": 0, "risks": "$data.risks", "id": 1},
                    ),
                )
                if len(res) and (
                    "Effective Admin" in res[0]["risks"] or "Admin" in res[0]["risks"]
                ):
                    identity_check1.append(
                        (res[0]["id"], "AWS.IAM.Role", ["global"]),
                    )
                    lambda_check1.append(
                        (
                            item["resource_id"],
                            "AWS.Lambda.Function",
                            item["regions"],
                        ),
                    )
                    check1 = True

        if check1:
            if lambda_check1:
                relations.append(
                    [
                        "Misconfiguration",
                        "Admin Access Compromise",
                        lambda_check1,
                    ],
                )
                relations.append(
                    [
                        "Admin Access Compromise",
                        "critical",
                        lambda_check1,
                    ],
                )

            if identity_check1:
                relations.append(
                    [
                        "Identity",
                        "Admin Access Compromise",
                        identity_check1,
                    ],
                )
                relations.append(
                    [
                        "Admin Access Compromise",
                        "critical",
                        identity_check1,
                    ],
                )

        return relations

    async def get_users_with_admin_policy_and_failing_no_mfa_old_access_keys(
        self,
        schema_name: str,
        latest_scan_ids: List[str],
    ) -> List[List]:
        check2_3 = False
        items = []
        relations: list[list[Any]] = []
        raw_check_2 = await DB.fetch_data(
            f"""
                SELECT *
                FROM {RESOURCE_TABLE.format(schema_name=schema_name)}
                WHERE
                    scan_id IN {tuple(latest_scan_ids)}
                    AND resource_type = 'AWS.IAM.User'
                    AND evaluation = 'non-compliant'
                    AND risk::text ilike '%Admin%'
            """
        )
        if raw_check_2 and len(raw_check_2):
            for item in raw_check_2:
                for rule in item["applicable_rules"]:
                    if (
                        rule["master_rule_id"] in ("CQ-AWS-IAM-037", "CQ-AWS-IAM-046")
                        and rule["rule_evaluation"] == "non-compliant"
                    ):
                        check2_3 = True
                        items.append(
                            (
                                item["resource_id"],
                                item["resource_type"],
                                item["regions"],
                            ),
                        )

        if check2_3:
            relations.append(
                ["Identity", "Admin Access Compromise", items],
            )
            relations.append(
                ["Admin Access Compromise", "critical", items],
            )

        return relations

    async def get_vul_public_ec2_instance_with_config_issue_and_risky_role(
        self,
        schema_name: str,
        latest_scan_ids: List[str],
    ) -> List[List]:
        check4 = False
        identity_check4 = []
        ec2_check4 = []

        relations: list[list[Any]] = []

        noSql_client = MongoDB._client
        client_db = noSql_client[f"shield_{schema_name}"]

        raw_check_4 = await DB.fetch_data(
            f"""
                SELECT resource_id, regions, applicable_rules
                FROM {RESOURCE_TABLE.format(schema_name=schema_name)}
                WHERE
                    scan_id IN {tuple(latest_scan_ids)}
                    AND is_public='{True}'
                    AND resource_type = 'AWS.EC2.Instance'
        """,
        )
        rids_to_check = []
        risk_cats = []
        if raw_check_4 and len(raw_check_4):
            for item in raw_check_4:
                for rule in item["applicable_rules"]:
                    if (
                        rule["master_rule_id"] == "CQ-AWS-EC2-055"
                        and rule["rule_evaluation"] == "non-compliant"
                    ):
                        rids_to_check.append(
                            (item["resource_id"], item["regions"]),
                        )
                        risk_cats.extend(["Misconfiguration"])

                        break

        if rids_to_check:
            for rid, regions in rids_to_check:
                res = list(
                    client_db["resource_details"].find(
                        {
                            "$and": [
                                {
                                    "scan_id": {
                                        "$in": latest_scan_ids,
                                    },
                                    "resource_id": rid,
                                    "resource_type": {
                                        "$eq": "AWS.EC2.Instance",
                                    },
                                },
                            ],
                        },
                        {
                            "_id": 0,
                            "iam_role": "$resource_configuration.iam_role",
                        },
                    ),
                )

                if not res:
                    continue

                role_to_check = res[0]["iam_role"]

                # check if admin risk is attached to this role
                res = list(
                    client_db["identity_roles"].find(
                        {
                            "$and": [
                                {
                                    "scan_id": {
                                        "$in": latest_scan_ids,
                                    },
                                    "data.name": {
                                        "$eq": role_to_check,
                                    },
                                },
                            ],
                        },
                        {"_id": 0, "risks": "$data.risks", "id": 1},
                    ),
                )
                if len(res) and (
                    "Effective Admin" in res[0]["risks"] or "Admin" in res[0]["risks"]
                ):
                    identity_check4.append(
                        (res[0]["id"], "AWS.IAM.Role", ["global"]),
                    )
                    ec2_check4.append(
                        (rid, "AWS.EC2.Instance", regions),
                    )
                    check4 = True

        if check4:
            if ec2_check4:
                for risk in risk_cats:
                    if risk != "Identity":
                        relations.append(
                            [
                                risk,
                                "Admin Access Compromise",
                                ec2_check4,
                            ],
                        )
                        relations.append(
                            [
                                "Admin Access Compromise",
                                "critical",
                                ec2_check4,
                            ],
                        )

            if identity_check4:
                relations.append(
                    [
                        "Identity",
                        "Admin Access Compromise",
                        identity_check4,
                    ],
                )
                relations.append(
                    [
                        "Admin Access Compromise",
                        "critical",
                        identity_check4,
                    ],
                )

        return relations

    def _flatten(self, xss: List[List]):
        return [x for xs in xss for x in xs]

    async def admin_access_compromise(self, schema_name, latest_scan_ids):
        """
        1. Public access to lambda function with a risky IAM role attached
            (admin &/or effective admin, Risky role here will be with IAM risks as effective admin & admin)
        2. Users with admin policy attached, old access keys not used for > 90 days, multiple access keys with NO MFA.
            (access key should be active)
        3. Users with admin policy attached, old access keys not used for > 90 days with NO MFA
            (access key should be active).
        4. Public access to a vulnerable EC2 instance via direct public IP, with configuration issues
            (# this is IMDSV1 failing rule - CQ-AWS-EC2-055) that has an IAM risky role attached.

        for point 2 & 3, we have a rule in scanner IAM-037 & IAM-046
        """
        relations = []
        r1, r2, r3 = await asyncio.gather(
            self.get_count_of_public_lambda_with_risky_role(
                schema_name,
                latest_scan_ids,
            ),
            self.get_users_with_admin_policy_and_failing_no_mfa_old_access_keys(
                schema_name,
                latest_scan_ids,
            ),
            self.get_vul_public_ec2_instance_with_config_issue_and_risky_role(
                schema_name,
                latest_scan_ids,
            ),
        )
        relations.extend([r1, r2, r3])
        return relations

    async def vulnerable_public_workloads(
        self,
        schema_name: str,
        latest_scan_ids: List[str],
    ) -> List[List]:
        """1. Public access to EC2 with a network AV vulnerability which has been also seen in CISA KEV with malware infection as well.
        2. Public vulnerable workload with network AV with Malware infection.
            -> for any cve in details column check details.Vector for AV:N (Network Vuln)

        ---- how to check malware infection?

        3. Public access to EC2 with a network AV vulnerability which has been also seen in CISA KEV (being exploited in the wild)
            -> public ec2.instance with vulnerabilities
            -> for any cve in details column check details.Vector for AV:N (Network Vuln)
            -> threat_trend.cisa == 1

        4. Public access to sensitive EC2 instance, with a CVE and and configuration issue (#this is IMDSV1 failing rule) that has an IAM risky role attached.
            -> sensitive ec2 instance means one with production=True and classification=Critical
            -> is_public = True
            -> EC2-055 rule failing
            -> vulnerable
            -> iam_role should have risk apart from effective admin / admin
        """
        vul_db = VULNERABILITY.format(schema_name=schema_name)
        resource_table = RESOURCE_TABLE.format(
            schema_name=schema_name,
        )

        check3 = []
        check4 = []
        identity_check4 = []

        # fetch all ec2.instance resource that have cve which is active
        vul_raw_data = await DB.fetch_data(
            f"""
                SELECT resource
                FROM {vul_db}
                WHERE
                    resource_type = 'AWS.EC2.Instance'
                    AND state = 'ACTIVE'
                    AND threat_trend->>'cisa'::text = '1'
                    AND details->>'Vector' like '%AV:N%'
        """,
        )
        if vul_raw_data and len(vul_raw_data):
            res_to_check = [item["resource"] for item in vul_raw_data]

            if len(res_to_check) == 1:
                res_to_check.append("0")

            if len(res_to_check):
                public_ec2_raw = await DB.fetch_data(
                    f"""
                        SELECT resource_id, scan_id, regions, resource_type
                        FROM {resource_table}
                        WHERE
                            scan_id in {tuple(latest_scan_ids)}
                            AND resource_id in {tuple(res_to_check)}
                            AND is_public='{True}'
                            AND resource_type='AWS.EC2.Instance'
                """,
                )

                if public_ec2_raw and len(public_ec2_raw):
                    for item in public_ec2_raw:
                        check3.append(
                            (
                                item["resource_id"],
                                item["resource_type"],
                                item["regions"],
                            ),
                        )

        vul_raw_data = await DB.fetch_data(
            f"""
                SELECT resource
                FROM {vul_db}
                WHERE
                    resource_type = 'AWS.EC2.Instance'
                    AND state = 'ACTIVE'
        """,
        )
        if vul_raw_data and len(vul_raw_data):
            res_to_check = [item["resource"] for item in vul_raw_data]

            if len(res_to_check) == 1:
                res_to_check.append("0")

            if len(res_to_check):
                public_ec2_raw = await DB.fetch_data(
                    f"""
                        SELECT resource_id, applicable_rules, regions, resource_type
                        FROM {resource_table}
                        WHERE
                            scan_id in {tuple(latest_scan_ids)}
                            AND resource_id in {tuple(res_to_check)}
                            AND is_public='{True}'
                            AND resource_type='AWS.EC2.Instance'
                            AND production='True'
                            AND classification='Critical'
                """,
                )

                final_ec2_res_to_check = []
                if public_ec2_raw and len(public_ec2_raw):
                    for item in public_ec2_raw:
                        for rule in item["applicable_rules"]:
                            if (
                                rule["master_rule_id"] == "CQ-AWS-EC2-055"
                                and rule["rule_evaluation"] == "non-compliant"
                            ):
                                final_ec2_res_to_check.append(
                                    (
                                        item["resource_id"],
                                        item["resource_type"],
                                        item["regions"],
                                    ),
                                )
                                break

                if final_ec2_res_to_check:
                    noSql_client = MongoDB._client
                    client_db = noSql_client[f"shield_{schema_name}"]

                    # fetch each resources' configuration and check for iam_role's risk
                    for rid, rtype, regions in final_ec2_res_to_check:
                        res = list(
                            client_db["resource_details"].find(
                                {
                                    "$and": [
                                        {
                                            "scan_id": {
                                                "$in": latest_scan_ids,
                                            },
                                            "resource_id": {
                                                "$eq": rid,
                                            },
                                            "resource_type": {
                                                "$eq": "AWS.EC2.Instance",
                                            },
                                        },
                                    ],
                                },
                                {
                                    "_id": 0,
                                    "iam_role": "$resource_configuration.iam_role",
                                    "id": 1,
                                },
                            ),
                        )

                        if not res:
                            continue

                        role_to_check = res[0]["iam_role"]

                        # check if admin risk is attached to this role
                        res = list(
                            client_db["identity_roles"].find(
                                {
                                    "$and": [
                                        {
                                            "scan_id": {
                                                "$in": latest_scan_ids,
                                            },
                                            "data.name": {
                                                "$eq": role_to_check,
                                            },
                                        },
                                    ],
                                },
                                {
                                    "_id": 0,
                                    "risks": "$data.risks",
                                    "id": 1,
                                },
                            ),
                        )
                        if len(res) and (
                            "Effective Admin" not in res[0]["risks"]
                            and "Admin" not in res[0]["risks"]
                        ):
                            check4.append((rid, rtype, regions))
                            identity_check4.append(
                                (
                                    res[0]["id"],
                                    "AWS.IAM.Role",
                                    ["global"],
                                ),
                            )

        relations = []
        if check3 or check4 or identity_check4:
            if check3:
                relations.append(
                    [
                        "Vulnerabilities",
                        "Vulnerable Public Workloads",
                        check3,
                    ],
                )
                relations.append(
                    [
                        "Vulnerable Public Workloads",
                        "critical",
                        check3,
                    ],
                )
            if check4:
                relations.append(
                    [
                        "Vulnerabilities",
                        "Vulnerable Public Workloads",
                        check4,
                    ],
                )
                relations.append(
                    [
                        "Vulnerable Public Workloads",
                        "critical",
                        check4,
                    ],
                )
            if identity_check4:
                relations.append(
                    [
                        "Identity",
                        "Vulnerable Public Workloads",
                        identity_check4,
                    ],
                )
                relations.append(
                    [
                        "Vulnerable Public Workloads",
                        "critical",
                        identity_check4,
                    ],
                )

        return relations

    async def data_exposure(
        self,
        schema_name: str,
        latest_scan_ids: list[str],
    ) -> List[List]:
        """Publicly Exposed Asset - S3, RDS, DynamoDB"""
        resource_table = RESOURCE_TABLE.format(
            schema_name=schema_name,
        )

        raw_data = await DB.fetch_data(
            f"""
                SELECT *
                FROM {resource_table}
                WHERE service_category in ('Storage') AND 
                scan_id in {tuple(latest_scan_ids)}
                AND is_public='{True}' AND evaluation='non-compliant'
            """,
        )

        local_map_of_risk_count = {"Misconfiguration": []}

        # FIXME: how are we populating this cache?
        # add this to populate cache script
        CACHE_KEY = f"is_public_resource_types_for_{schema_name}"
        ie_resource_type_masterid = cache.get(CACHE_KEY) or {}

        if raw_data and len(raw_data):
            for item in raw_data:
                for rule in item["applicable_rules"]:
                    if (
                        item["resource_type"] in ie_resource_type_masterid
                        and rule["master_rule_id"]
                        in ie_resource_type_masterid[item["resource_type"]]  # type: ignore
                        and rule["rule_evaluation"] == "non-compliant"
                    ):
                        # insert resource for each failing IE rule
                        local_map_of_risk_count["Misconfiguration"].append(
                            (
                                item["resource_id"],
                                item["resource_type"],
                                item["regions"],
                            ),
                        )

        if local_map_of_risk_count:
            res = []
            for risk, items in local_map_of_risk_count.items():
                if items:
                    res.append(
                        [risk, "Data Exposure", items],
                    )
                    res.append(["Data Exposure", "critical", items])
            return res
        else:
            return []

    async def _run(
        self,
        schema_name: str,
        scan_id: str,
        environment_id: str,
        cloud_provider: str = "aws",
    ):
        """Sankey Diagram:
        1. starting names will be names of the rule category
        2. count of failing rule (risk) belonging to the rule category
        3. this will lead to a pre-defined check
        4. this will lead to a severity label
        """
        try:
            latest_scan_ids = [scan_id]

            if len(latest_scan_ids) == 1:
                latest_scan_ids.append("0")

            init_res = []

            # this will give us mapping of all the rules categories with severity breakup for direct one to three
            # NOTE: we have decided not to use risk categories
            # risk_cat_count = self.get_risks_count_for_each_rule_category(
            #     schema_name, latest_scan_ids
            # )

            (
                data_exposure_res,
                admin_access_res,
                vul_public_workloads,
            ) = await asyncio.gather(
                self.data_exposure(
                    schema_name,
                    latest_scan_ids,
                ),
                self.admin_access_compromise(
                    schema_name,
                    latest_scan_ids,
                ),
                self.vulnerable_public_workloads(
                    schema_name,
                    latest_scan_ids,
                ),
            )

            if data_exposure_res:
                init_res.extend(data_exposure_res)

            if admin_access_res:
                init_res.extend(admin_access_res)

            if vul_public_workloads:
                init_res.extend(vul_public_workloads)

            return {
                "error": False,
                "data": init_res,
                "account_id": environment_id,
                "scan_id": scan_id,
            }

        except Exception:
            return {
                "error": True,
                "data": [],
                "account_id": environment_id,
                "scan_id": scan_id,
                "message": traceback.format_exc(),
            }

    @classmethod
    async def insert_pfunnel_data_to_mongo(
        cls,
        schema_name: str,
        scan_id: str,
        environment_id: str,
        cloud_provider: str = "aws",
    ):
        try:
            slog.info("RUNNING Pfunnel CHECKS")

            pfunnel_data = await cls.run(
                schema_name, scan_id, environment_id, cloud_provider
            )

            _ = MongoDB.bulk_insert(schema_name, "pfunnel", [pfunnel_data])
            slog.bind(number_of_attack_paths=len(pfunnel_data.get("data") or [])).info(
                "INSERTED pfunnel data into mongo"
            )

            slog.debug("NOW INSERTING ATTACK PATH LABEL FOR RESOURCES")
            if pfunnel_data.get("data"):
                # there will only ever be even number of entries
                # we need to only consume the ones at index: 1, 3, 5, ...
                raw_data = pfunnel_data.get("data") or []
                map_of_res_to_ap = {}
                for i in range(0, len(raw_data), 2):
                    attack_dict = {}
                    attack_path_label = raw_data[i][1]
                    attack_dict["name"] = attack_path_label
                    attack_dict["severity"] = raw_data[i + 1][1]
                    resources: List[Tuple[int, int, List[str]]] = raw_data[i][2]

                    for resource in resources:
                        resource_key = (
                            resource[0],
                            resource[1],
                            "_".join(sorted(resource[2])),
                        )

                        if resource_key not in map_of_res_to_ap:
                            map_of_res_to_ap[resource_key] = []

                        if attack_dict not in map_of_res_to_ap[resource_key]:
                            map_of_res_to_ap[resource_key].append(attack_dict)

                severity_map = {
                    "critical": 5,
                    "high": 4,
                    "medium": 3,
                    "low": 2,
                    "info": 1,
                }

                if len(map_of_res_to_ap.keys()):
                    for resource, ap_labels in map_of_res_to_ap.items():
                        highest_severity = "info"
                        for ap_label in ap_labels:
                            sev = ap_label.get("severity")
                            if severity_map.get(sev, 0) > severity_map.get(
                                highest_severity, 0
                            ):
                                highest_severity = sev

                        if await DB.execute_query(
                            f"""
                                UPDATE {RESOURCE_TABLE.format(schema_name=schema_name)}
                                    SET
                                        attack_path_labels = '{ujson.dumps(ap_labels)}',
                                        shield_severity = '{highest_severity}'
                                    WHERE
                                        resource_id='{resource[0]}' 
                                        AND resource_type = '{resource[1]}'
                                        AND scan_id='{scan_id}'
                            """
                        ):
                            slog.bind(
                                resource=resource[0], attack_path_labels=ap_labels
                            ).info("UPDATED WITH ATTACK PATH(s)")
                        else:
                            slog.bind(
                                resource=resource[0], attack_path_labels=ap_labels
                            ).warning("FAILED TO UPDATED WITH ATTACK PATH(s)")

                slog.debug("INSERTING ATTACK PATH LABEL FOR RESOURCES --- DONE")

            else:
                slog.debug("NOTHING TO INSERT")

        except Exception as e:
            slog.error(f"PFUNNEL - {e}", exc_info=True)
