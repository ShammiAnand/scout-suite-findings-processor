from scan_compute.utils import enum
from scan_compute.utils.logging import logger
from dataclasses import dataclass, field
from typing import Any, List, Dict, Literal, Set
from scan_compute.utils.cache import cache
from scan_compute.constants import cache_keys as ckeys
from collections import deque
from scan_compute.types.constant import SERVICES


type_logger = logger.bind(name="CSPM Report Parser")


@dataclass
class Finding:
    service: str
    rule_name: str
    affected_resource_type: str
    master_rule_id: str
    risk_category: List[str]
    flagged_items: int
    checked_items: int
    items: List[str]  # stores non-compliant resources
    display_path: str
    severity: str

    evaluation: Literal["compliant", "non-compliant", "not-applicable"] = field(
        init=False
    )

    compliant_items: List[str] = field(init=False, default_factory=list)

    def __post_init__(self):
        if self.checked_items == 0:
            self.evaluation = "not-applicable"
        elif self.flagged_items == 0:
            self.evaluation = "compliant"
        else:
            self.evaluation = "non-compliant"


@dataclass
class CSPMReport:
    """Scout Suite Report Parser for AWS/GCP"""

    provider_code: enum.CloudProvider
    account_id: str
    service_list: List[SERVICES]
    services: Dict[str, Any]
    service_findings: List[Finding] = field(init=False, default_factory=list)
    all_items: Set[str] = field(init=False, default_factory=set)

    # TODO: do we require all the below attributes or can it be reduced to a generalised mapping?
    _processed_display_path: Set[str] = field(init=False, default_factory=set)
    _display_path_to_items: Dict[str, List[str]] = field(
        init=False, default_factory=dict
    )
    _display_path_to_resource_type: Dict[str, str] = field(
        init=False, default_factory=dict
    )
    _item_to_failed_rule: Dict[str, List[Finding]] = field(
        init=False, default_factory=dict
    )
    _item_to_resource_type: Dict[str, str] = field(init=False, default_factory=dict)
    _resource_type_to_findings: Dict[str, List[Finding]] = field(
        init=False, default_factory=dict
    )
    _resource_type_to_items: Dict[str, List[str]] = field(
        init=False, default_factory=dict
    )

    # TODO: implement selected compliances flow; i.e when the scan only runs a subset of
    # compliances; that's when we only process the controls of the selected compliance

    def __post_init__(self):
        self.service_findings = []
        self._process_initial_findings()

    def process_module_findings(self, module_findings: List[Finding]):
        for finding in module_findings:
            parsed_items = self._conform_items_to_display_path(
                finding.items, finding.display_path
            )
            finding.items = parsed_items
            self.service_findings.append(finding)
            self._update_all_mappings(finding)

    def _process_initial_findings(self) -> None:
        """initialises all the mappings and processes initial finidings for the report"""
        for service, raw_service_findings in self.services.items():
            for rule_name, finding in raw_service_findings["findings"].items():
                try:
                    parsed_items = self._conform_items_to_display_path(
                        finding["items"], finding["display_path"]
                    )
                    finding_obj = Finding(
                        service=service,
                        rule_name=rule_name,
                        affected_resource_type=finding["affected_resource_type"],
                        master_rule_id=finding["master_rule_id"],
                        risk_category=finding["risk_category_new"],
                        flagged_items=finding["flagged_items"],
                        checked_items=finding["checked_items"],
                        items=parsed_items,
                        display_path=finding["display_path"],
                        severity=finding["risk_level"],
                    )
                    self.service_findings.append(finding_obj)

                except KeyError as e:
                    type_logger.error(
                        f"error while getting {e} in {rule_name} for {service}",
                    )
                    continue

                self._update_all_mappings(finding_obj)

    def _parse_json_path(self, data: Dict[str, Any], path: str) -> List[str]:
        def traverse(
            current_data: Any, path_parts: deque, current_path: List[str]
        ) -> List[str]:
            if not path_parts:
                _item = ".".join(current_path)
                cache.set(
                    ckeys.DISPLAY_PATH_TO_RESOURCE.format(
                        account_id=self.account_id, display_path=_item
                    ),
                    current_data,
                )
                return [_item]

            current_part = path_parts.popleft()
            results = []

            if current_part == "id":
                if isinstance(current_data, dict):
                    for key, value in current_data.items():
                        new_path = current_path + [key]
                        results.extend(traverse(value, path_parts.copy(), new_path))
                else:
                    return []
            elif isinstance(current_data, dict) and current_part in current_data:
                new_path = current_path + [current_part]
                results.extend(
                    traverse(current_data[current_part], path_parts, new_path)
                )
            else:
                return []

            return results

        path_parts = deque(path.split("."))
        return traverse(data, path_parts, [])

    def _process_all_resources_for_display_path(
        self, display_path: str, resource_type: str
    ):
        if display_path not in self._processed_display_path:
            type_logger.debug("PROCESSING: %s", display_path)

            items = self._parse_json_path(self.services, display_path)  # type: ignore
            self.all_items.update(items)

            for item in items:
                self._item_to_resource_type[item] = resource_type

            if resource_type not in self._resource_type_to_items:
                self._resource_type_to_items[resource_type] = []

            self._resource_type_to_items[resource_type].extend(items)

            type_logger.debug(f"FOUND {len(items)} ITEMS", display_path=display_path)
            self._processed_display_path.add(display_path)

            self._display_path_to_items[display_path] = items

    def get_item_to_resource_type(self, item: str) -> str:
        return self._item_to_resource_type.get(item) or "NO_RESOURCE_TYPE"

    def _conform_items_to_display_path(self, items: List[str], display_path: str):
        """ignores extra depth keys that are not present in the display path"""
        display_path_len = len(display_path.split("."))
        parsed_items = []

        for item in items:
            if len(item.split(".")) != display_path_len:
                parsed_items.append(".".join(item.split(".")[:display_path_len]))
            else:
                parsed_items.append(item)

        return parsed_items

    def _update_all_mappings(self, finding_obj: Finding) -> None:
        self._display_path_to_resource_type[finding_obj.display_path] = (
            finding_obj.affected_resource_type
        )
        self._process_all_resources_for_display_path(
            finding_obj.display_path, finding_obj.affected_resource_type
        )

        if finding_obj.affected_resource_type not in self._resource_type_to_findings:
            self._resource_type_to_findings[finding_obj.affected_resource_type] = [
                finding_obj
            ]
        else:
            self._resource_type_to_findings[finding_obj.affected_resource_type].append(
                finding_obj
            )

        for item in finding_obj.items:
            if item not in self._item_to_failed_rule:
                self._item_to_failed_rule[item] = []
            self._item_to_failed_rule[item].append(finding_obj)
