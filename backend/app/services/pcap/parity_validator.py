from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np
from app.schemas.flows import FlowFeaturesInput

@dataclass
class ParityMetrics:
    """Per-feature parity statistical summary."""
    feature_name: str
    count: int
    mean_abs_error: float
    median_abs_error: float
    p90_abs_error: float
    p95_abs_error: float
    max_abs_error: float
    mean_rel_error: float
    median_rel_error: float
    p95_rel_error: float
    max_rel_error: float

class PcapParityValidator:
    """Evaluates empirical statistical parity between reconstructed PCAP flows and reference flow records."""

    @staticmethod
    def evaluate_feature_parity(
        reconstructed_flows: List[FlowFeaturesInput],
        reference_flows: List[FlowFeaturesInput],
    ) -> Dict[str, ParityMetrics]:
        """Compute detailed absolute and relative error distributions across all 48 canonical features."""
        if len(reconstructed_flows) != len(reference_flows):
            raise ValueError(
                f"Sample size mismatch: {len(reconstructed_flows)} reconstructed flows vs "
                f"{len(reference_flows)} reference flows."
            )

        if not reconstructed_flows:
            return {}

        feature_keys = FlowFeaturesInput.model_fields.keys()
        results: Dict[str, ParityMetrics] = {}

        for key in feature_keys:
            recon_vals = np.array([getattr(f, key) for f in reconstructed_flows], dtype=np.float64)
            ref_vals = np.array([getattr(f, key) for f in reference_flows], dtype=np.float64)

            abs_errors = np.abs(recon_vals - ref_vals)
            # Safe relative error with epsilon
            rel_errors = abs_errors / (np.abs(ref_vals) + 1e-6)

            results[key] = ParityMetrics(
                feature_name=key,
                count=len(recon_vals),
                mean_abs_error=float(np.mean(abs_errors)),
                median_abs_error=float(np.median(abs_errors)),
                p90_abs_error=float(np.percentile(abs_errors, 90)),
                p95_abs_error=float(np.percentile(abs_errors, 95)),
                max_abs_error=float(np.max(abs_errors)),
                mean_rel_error=float(np.mean(rel_errors)),
                median_rel_error=float(np.median(rel_errors)),
                p95_rel_error=float(np.percentile(rel_errors, 95)),
                max_rel_error=float(np.max(rel_errors)),
            )

        return results
