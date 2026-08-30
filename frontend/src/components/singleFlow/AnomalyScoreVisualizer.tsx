import React from 'react';
import { Activity, AlertTriangle, ShieldCheck } from 'lucide-react';
import { FlowPredictionResponse } from '../../types/inference';
import { formatPercent } from '../../utils/formatters';

interface AnomalyScoreVisualizerProps {
  prediction: FlowPredictionResponse;
}

export const AnomalyScoreVisualizer: React.FC<AnomalyScoreVisualizerProps> = ({ prediction }) => {
  const isAnom = prediction.is_statistical_anomaly;
  const normScore = prediction.normalized_anomaly_score;
  const rawScore = prediction.raw_decision_score;
  const threshold = prediction.calibrated_threshold ?? 0.051838;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-purple-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Statistical Anomaly Detector (Isolation Forest)
          </h4>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Model: {prediction.anomaly_model_key}
        </span>
      </div>

      {/* Metric Grid */}
      <div className="grid grid-cols-2 gap-3">
        {/* Normalized Anomaly Score */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase">Normalized Display Score</div>
          <div className={`text-2xl font-bold font-mono mt-1 ${normScore >= 0.7 ? 'text-amber-400' : 'text-slate-200'}`}>
            {normScore.toFixed(4)}
          </div>
          <p className="text-[10px] text-slate-400 mt-1">Scale [0.0 = Normal, 1.0 = Highly Anomalous]</p>
        </div>

        {/* Raw Decision Score vs Calibrated Threshold */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase">Raw Decision Score</div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-1">
            {rawScore.toFixed(5)}
          </div>
          <p className="text-[10px] text-slate-400 mt-1">
            Threshold (α=0.01): <strong className="text-slate-300">{threshold.toFixed(5)}</strong>
          </p>
        </div>
      </div>

      {/* Visual Gauge Bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-xs text-slate-400">
          <span>Anomaly Intensity Gauge</span>
          <span className="font-semibold text-slate-200 font-mono">{formatPercent(normScore)}</span>
        </div>
        <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden p-0.5 border border-slate-800 flex">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              normScore >= 0.70
                ? 'bg-gradient-to-r from-amber-500 to-red-500'
                : normScore >= 0.40
                ? 'bg-gradient-to-r from-blue-500 to-amber-500'
                : 'bg-emerald-500'
            }`}
            style={{ width: `${Math.min(100, Math.max(5, normScore * 100))}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-slate-400">
          <span>0.0 (Normal Pattern)</span>
          <span>0.70 (Policy Anomaly Gate)</span>
          <span>1.0 (Extreme Deviation)</span>
        </div>
      </div>

      {/* Anomaly Flag Verdict */}
      <div className={`p-3 rounded-lg border flex items-center gap-3 ${
        isAnom
          ? 'bg-amber-950/50 border-amber-600/60 text-amber-200'
          : 'bg-slate-950/60 border-slate-800 text-slate-300'
      }`}>
        {isAnom ? (
          <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
        ) : (
          <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />
        )}
        <div className="text-xs">
          <span className="font-bold">
            {isAnom ? 'Statistical Anomaly Flagged' : 'Within Normal Empirical Variance'}
          </span>
          <p className="text-[11px] text-slate-400 mt-0.5">
            {isAnom
              ? 'Raw decision score is below empirical threshold. Traffic exhibits significant deviation from baseline benign behavior.'
              : 'Traffic aligns with standard benign multidimensional distribution parameters.'}
          </p>
        </div>
      </div>
    </div>
  );
};
