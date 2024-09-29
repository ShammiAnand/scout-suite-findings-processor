from typing import Dict, Any, List
from scan_compute.services.parsers.scan_report_parser import Finding
from scan_compute.types.scan import BaseModule
from scan_compute.utils.enum import CloudProvider


class ModuleProcessor:
    @staticmethod
    async def process_modules(
        cloud_provider: CloudProvider,
        account_id: str,
        scan_id: str,
        scan_report: Dict[str, Any],
    ) -> List[Finding]:
        """Runs all applicable modules and aggregates their findings"""
        modules: List[BaseModule] = []

        # TODO: parallel processing of all modules
        findings = []
        for module in modules:
            if await module.is_enabled():
                findings.extend(await module.run())

        return findings
