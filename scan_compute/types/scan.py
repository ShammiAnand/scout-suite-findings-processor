"""Types."""

from dataclasses import dataclass
from typing import Any, List, Dict


from scan_compute.utils import enum
from scan_compute.utils.logging import logger
from scan_compute.services.parsers.scan_report_parser import Finding


type_logger = logger.bind(name="Scan Types")


@dataclass
class ScanStartPayload:
    """Scan Start Payload."""

    bucket_name: str
    scan_id: str
    account_id: str
    schema_name: str
    scan_type: str
    cloud_provider: str


@dataclass
class RuleName:
    rule_file_name: str


@dataclass
class CloudResource:
    resource_id: str
    resource_type: str
    regions: List[str]
    resource_configuration: Dict[str, Any]


class BaseModule:
    """represents the base module that can be integrated to the scan flow"""

    def __init__(
        self,
        cloud_provider: enum.CloudProvider,
        account_id: str,
        scan_id: str,
        scan_report: Dict[str, Any],
    ) -> None:
        self._scan_report = scan_report
        self.account_id = account_id
        self.scan_id = scan_id
        self._cloud_provider = cloud_provider

    async def is_enabled(self) -> bool:
        return False

    async def run(self) -> List[Finding]:
        raise NotImplementedError("since each module has its own way of checking")
