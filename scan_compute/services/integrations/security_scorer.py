from __future__ import annotations

from scan_compute.constants import tables
from scan_compute.utils.database import DB
from typing import Dict


class SecurityScorer:
    """calculates security score for an account based on the compliance posture"""

    @classmethod
    async def get_resource_severity_count(
        cls, schema_name: str, scan_id: str
    ) -> Dict[str, int]:
        output_dic = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_severity = 0

        if (
            severity_count_data := await DB.fetch_data(
                f"""
                SELECT
                    shield_severity as severity, COUNT(*) As count
                    FROM {tables.RESOURCE_TABLE.format(schema_name=schema_name)}
                WHERE scan_id = '{scan_id}' and evaluation = 'non-compliant'
                GROUP BY shield_severity
            """
            )
        ) and len(severity_count_data):
            for severity_data in severity_count_data:
                output_dic[severity_data["severity"]] = severity_data["count"]

        if (
            total_count_data := await DB.fetch_data(
                f"""
                    SELECT count(id) as TOTAL_SEVERITY
                    FROM {tables.RESOURCE_TABLE.format(schema_name=schema_name)}
                    WHERE scan_id = '{scan_id}' and (evaluation = 'non-compliant')
                """
            )
        ) and len(total_count_data):
            total_severity = total_count_data[0]["total_severity"]

        output_dic["total"] = total_severity
        return output_dic

    @classmethod
    async def get_security_score(cls, schema_name: str, scan_id: str) -> float:
        """calculates the security score from data inserted into tables"""
        security_score = 1
        severity_dic = await cls.get_resource_severity_count(schema_name, scan_id)

        critical_value = severity_dic["critical"]
        high_value = severity_dic["high"]
        medium_value = severity_dic["medium"]
        low_value = severity_dic["low"]
        total_value = severity_dic["total"]

        cw = 1
        hw = cw / 1.5
        mw = cw / 3
        lw = cw / 5

        weighted_sum = (
            (critical_value * cw)
            + (high_value * hw)
            + (medium_value * mw)
            + (low_value * lw)
        )

        # assuming all non-compliant are critical
        max_weighted_sum = total_value * cw
        security_score = 1 - (weighted_sum / max_weighted_sum)

        return round(float(security_score * 100))
