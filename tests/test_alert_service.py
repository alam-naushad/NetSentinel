"""Unit tests for Configurable Alert Policy and Triage Service."""

from __future__ import annotations

import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.config import settings
from app.db.models.security_event import SecurityEvent
from app.services.alert_service import AlertService


class AlertServiceTests(unittest.TestCase):
    """Test suite verifying configurable policy rules for alert generation."""

    def _create_event(
        self,
        predicted_family: str = "BENIGN",
        confidence: float = 0.95,
        risk_score: int = 15,
        severity: str = "LOW",
        triage_status: str = "NORMAL",
    ) -> SecurityEvent:
        return SecurityEvent(
            id=uuid.uuid4(),
            event_timestamp=datetime.now(timezone.utc),
            source_channel="REST_EVAL",
            predicted_family=predicted_family,
            class_confidence=confidence,
            normalized_anomaly_score=0.10,
            is_statistical_anomaly=False,
            risk_score=risk_score,
            severity=severity,
            triage_status=triage_status,
            class_probabilities={predicted_family: confidence},
            feature_vector={"destination_port": 80.0},
        )

    def test_benign_normal_event_does_not_generate_alert(self):
        """Standard normal traffic with low risk does not trigger an alert."""
        event = self._create_event(predicted_family="BENIGN", confidence=0.99, risk_score=10, severity="LOW", triage_status="NORMAL")
        alert = AlertService.create_alert_for_event(event)
        self.assertIsNone(alert)

    def test_high_confidence_known_attack_generates_alert(self):
        """Confident known attack triggers an alert with correct type and severity."""
        event = self._create_event(
            predicted_family="DDOS",
            confidence=0.98,
            risk_score=85,
            severity="CRITICAL",
            triage_status="KNOWN_ATTACK",
        )
        alert = AlertService.create_alert_for_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "KNOWN_ATTACK_DDOS")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.disposition, "OPEN")
        self.assertEqual(len(alert.history), 1)
        self.assertEqual(alert.policy_version_applied, settings.ALERT_POLICY_VERSION)

    def test_unknown_anomaly_generates_alert_when_policy_enabled(self):
        """Statistical unknown anomaly triggers an alert if ALERT_ON_UNKNOWN_ANOMALY=True."""
        event = self._create_event(
            predicted_family="BENIGN",
            confidence=0.60,
            risk_score=55,
            severity="MEDIUM",
            triage_status="UNKNOWN_ANOMALY",
        )
        alert = AlertService.create_alert_for_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "UNKNOWN_STATISTICAL_ANOMALY")
        self.assertEqual(alert.severity, "MEDIUM")

    def test_high_risk_score_escalates_even_with_low_classifier_confidence(self):
        """An event with risk_score >= ALERT_RISK_THRESHOLD generates an alert."""
        event = self._create_event(
            predicted_family="BOT",
            confidence=0.70,  # Below 0.80 confidence threshold
            risk_score=70,    # Above 65 risk threshold
            severity="HIGH",
            triage_status="UNKNOWN_ANOMALY",
        )
        alert = AlertService.create_alert_for_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "ATTACK_BOT")


if __name__ == "__main__":
    unittest.main()
