"""Enum."""

from __future__ import annotations
from enum import StrEnum


class CloudProvider(StrEnum):
    """Cloud Providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"

    @staticmethod
    def from_str(label: str) -> CloudProvider:
        if label.lower() == "aws":
            return CloudProvider.AWS
        elif label.lower() == "gcp":
            return CloudProvider.GCP
        elif label.lower() == "azure":
            return CloudProvider.AZURE
        else:
            raise Exception(f"{label} IS NOT AN OPTION IN CloudProvider ENUM")

    def to_str(self) -> str:
        return self.value


class ScanType(StrEnum):
    """Scan Types."""

    MANUAL = "Manual"
    RTM = "RTM"

    @staticmethod
    def from_str(label: str) -> ScanType:
        if label.lower() == "manual":
            return ScanType.MANUAL
        elif label.lower() == "rtm":
            return ScanType.RTM
        else:
            raise Exception(f"{label} IS NOT AN OPTION IN ScanType ENUM")


class ScanStatus(StrEnum):
    """Scan Statuses."""

    NOT_STARTED = "notstarted"
    IN_PROGRESS = "inprogress"
    COMPLETED = "complete"
    FAILED = "fail"
