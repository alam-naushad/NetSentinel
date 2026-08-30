"""Stable domain types shared by API and decision logic."""

from enum import StrEnum


class DetectionStatus(StrEnum):
    NORMAL = "NORMAL"
    KNOWN_ATTACK = "KNOWN_ATTACK"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
