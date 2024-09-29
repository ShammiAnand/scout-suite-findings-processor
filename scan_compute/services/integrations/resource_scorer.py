from dataclasses import dataclass
from typing import List, Dict, Any, Literal
from scan_compute.utils.logging import logger

slog = logger.bind(name="CQ Shield Priority")


class SeverityCalculator:
    @staticmethod
    def calculate(
        scores: List[float],
    ) -> Literal["critical", "high", "medium", "low", "info"]:
        total_score = sum(scores)
        if total_score >= 8:
            return "critical"
        elif 6 <= total_score < 8:
            return "high"
        elif 3 <= total_score < 6:
            return "medium"
        elif 0.1 <= total_score < 3:
            return "low"
        else:
            return "info"


@dataclass
class ResourceData:
    environment_id: str
    environment_tags: List[str]
    environment_name: str
    account_id: str
    scan_id: str
    cloud_provider: str
    evaluation: str
    applicable_rules: List[Dict[str, Any]]
    resource_id: str
    resource_type: str
    service: str
    service_category: str
    severity: str
    resource_name: str
    tags: List[Dict[str, str]]
    regions: List[str]
    region: List[str]
    severity: str
    resource_configuration: Dict[str, Any]
    violations: int
    classification: str
    production: str
    is_public: bool
    attack_path_labels: List[str]
    risk: List[str]
    last_updated: str
    applicable_compliances: List[str]


class BaseCheck:
    """represent the check; requires a weight and reason and a run method to process the check"""

    def __init__(self, weight: float, reason: str | None = None):
        self.weight = weight

        # NOTE: reason has to be defined in each check implementation
        self.reason = reason

    def run(self, resource: ResourceData) -> float:
        raise NotImplementedError


class PublicExposureCheck(BaseCheck):
    """checks if a resource is publicly exposed"""

    def run(self, resource: ResourceData) -> float:
        return 10 if resource.is_public else 0


class ResourceTagCheck(BaseCheck):
    """if there are resource level tags to signify critical/prod infra related resources"""

    def run(self, resource: ResourceData) -> float:
        return (
            10
            if resource.classification == "Critical" and resource.production == "True"
            else 0
        )


class EnvTagCheck(BaseCheck):
    """a PROD environment should increase the resource security score"""

    def run(self, resource: ResourceData) -> float:
        env_tags_weight = {
            "Production": 10,
            "Development": 3,
            "Staging": 5,
            "Hot-Fix": 4,
            "Testing": 5,
        }
        return (
            env_tags_weight[resource.environment_tags[0]]
            if resource.environment_tags
            and resource.environment_tags[0] in env_tags_weight
            else 0
        )


class ResourceStateCheck(BaseCheck):
    """applicable only for RDS and EC2 services"""

    def run(self, resource: ResourceData) -> float:
        try:
            if (
                resource.service in ["AWS EC2", "AWS RDS"]
                and resource.resource_configuration.get("State", {}).get("Name", "")
                == "running"
            ):
                return 10

            return 0

        except (KeyError, ValueError, AttributeError) as e:
            slog.error(
                f"error while checking resource_configuration for ec2 or rds service {e}"
            )
            return 0


class MisconfigurationCheck(BaseCheck):
    """highest severity rule failing"""

    def run(self, resource: ResourceData) -> float:
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 2,
        }
        return (
            severity_weights.get(resource.severity.lower(), 0)
            if resource.severity
            else 0
        )


class ChecksProcessor:
    _checks = [
        PublicExposureCheck(weight=0.3, reason="public access to this resource"),
        ResourceTagCheck(weight=0.3),
        EnvTagCheck(weight=0.1),
        ResourceStateCheck(weight=0.05, reason="checks running state for RDS and EC2"),
        MisconfigurationCheck(weight=0.25),
    ]

    @classmethod
    def process_checks(
        cls, resource: ResourceData
    ) -> Literal["critical", "high", "medium", "low", "info"]:
        scores = [check.run(resource) * check.weight for check in cls._checks]
        return SeverityCalculator.calculate(scores)
