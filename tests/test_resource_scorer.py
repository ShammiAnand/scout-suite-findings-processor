import pytest
from datetime import datetime
from scan_compute.services.integrations.resource_scorer import (
    ResourceData,
    SeverityCalculator,
    PublicExposureCheck,
    ResourceTagCheck,
    EnvTagCheck,
    ResourceStateCheck,
    MisconfigurationCheck,
    ChecksProcessor,
)


@pytest.fixture
def resource_data():
    sample_resource_data = {
        "environment_id": "941086635301",
        "environment_name": "SOME NAME",
        "account_id": "941086635301",
        "environment_tags": ["Production"],
        "scan_id": "",
        "cloud_provider": "aws",
        "severity": "HIGH",
        "evaluation": "non-compliant",
        "applicable_rules": [{"severity": "high", "master_rule_id": "CQ-AWS-EC2-025"}],
        "resource_id": "i-1234567890abcdef0",
        "resource_type": "AWS.EC2.Instance",
        "service": "AWS EC2",
        "service_category": "Compute",
        "resource_name": "MyEC2Instance",
        "tags": [{"Key": "Environment", "Value": "Production"}],
        "regions": ["us-west-2"],
        "region": ["us-west-2"],
        "resource_configuration": {},
        "violations": 1,
        "classification": "Critical",
        "production": "True",
        "is_public": True,
        "attack_path_labels": [],
        "risk": ["Network"],
        "last_updated": datetime.now().strftime("%Y-%m-%d , %H:%M:%S"),
        "applicable_compliances": [],
    }
    return ResourceData(**sample_resource_data)


def test_severity_calculator():
    assert SeverityCalculator.calculate([10, 5, 3]) == "critical"
    assert SeverityCalculator.calculate([1, 3, 2]) == "high"
    assert SeverityCalculator.calculate([4, 2, 1]) == "high"
    assert SeverityCalculator.calculate([2, 1, 0]) == "medium"


def test_public_exposure_check(resource_data):
    check = PublicExposureCheck(weight=0.3, reason="public access to this resource")
    assert check.run(resource_data) == 10
    resource_data.is_public = False
    assert check.run(resource_data) == 0


def test_resource_tag_check(resource_data):
    check = ResourceTagCheck(weight=0.3)
    assert check.run(resource_data) == 10
    resource_data.classification = "Non-Critical"
    resource_data.production = "False"
    assert check.run(resource_data) == 0


def test_env_tag_check(resource_data):
    check = EnvTagCheck(weight=0.1)
    assert check.run(resource_data) == 10
    resource_data.environment_tags = ["Development"]
    assert check.run(resource_data) == 3


def test_resource_state_check(resource_data):
    check = ResourceStateCheck(
        weight=0.05, reason="checks running state for RDS and EC2"
    )
    resource_data.resource_configuration["State"] = {"Name": "stopped"}
    assert check.run(resource_data) == 0


def test_misconfiguration_check(resource_data):
    check = MisconfigurationCheck(weight=0.25)
    assert check.run(resource_data) == 7
    resource_data.severity = "medium"
    assert check.run(resource_data) == 5


def test_checks_processor(resource_data):
    severity = ChecksProcessor.process_checks(resource_data)
    assert severity == "critical"
