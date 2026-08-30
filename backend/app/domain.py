"""Stable domain types shared by API, ML inference, and decision logic."""

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


class ModelRole(StrEnum):
    SUPERVISED_CLASSIFIER = "SUPERVISED_CLASSIFIER"
    STATISTICAL_ANOMALY_DETECTOR = "STATISTICAL_ANOMALY_DETECTOR"


class ModelProtocol(StrEnum):
    PROTOCOL_A = "A"
    PROTOCOL_B = "B"


class DeploymentTier(StrEnum):
    PRODUCTION_DEFAULT = "PRODUCTION_DEFAULT"
    PRODUCTION_ALTERNATIVE = "PRODUCTION_ALTERNATIVE"
    RESEARCH_EVALUATION = "RESEARCH_EVALUATION"


class AttackFamily(StrEnum):
    BENIGN = "BENIGN"
    DOS = "DOS"
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    BOT = "BOT"
    WEB_ATTACK = "WEB_ATTACK"
    INFILTRATION = "INFILTRATION"
    UNKNOWN = "UNKNOWN"
