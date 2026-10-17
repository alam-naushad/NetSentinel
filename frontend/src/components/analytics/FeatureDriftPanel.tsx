import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  Clock,
  HelpCircle,
  Info,
  RefreshCw,
  Search,
  Sliders,
} from 'lucide-react';
import { DriftEvaluationResponse, FeatureDriftResult } from '../../types/drift';
import { fetchTelemetryDrift } from '../../api/driftApi';

export const FeatureDriftPanel: React.FC = () => {
  const [data, setData] = useState<DriftEvaluationResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [showAllFeatures, setShowAllFeatures] = useState<boolean>(false);

  const loadDriftData = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetchTelemetryDrift(500, 'PCAP_BATCH');
      setData(resp);
    } catch (err: any) {
      setError(err?.message || 'Failed to load feature drift telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDriftData();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'STABLE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950/70 border border-emerald-600/40 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            STABLE DISTRIBUTION
          </span>
        );
      case 'MODERATE_DRIFT':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-950/70 border border-amber-600/50 text-amber-300">
            <AlertTriangle className="w-3.5 h-3.5" />
            MODERATE SHIFT
          </span>
        );
      case 'SIGNIFICANT_DRIFT':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-950/80 border border-red-600/60 text-red-300">
            <AlertCircle className="w-3.5 h-3.5" />
            SIGNIFICANT DRIFT
          </span>
        );
      case 'INSUFFICIENT_DATA':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 border border-slate-700 text-slate-300">
            <HelpCircle className="w-3.5 h-3.5" />
            INSUFFICIENT SAMPLE
          </span>
        );
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'STABLE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-emerald-950/60 border border-emerald-700/50 text-emerald-400">
            Stable
          </span>
        );
      case 'MODERATE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-amber-950/60 border border-amber-700/50 text-amber-300">
            Moderate
          </span>
        );
      case 'SIGNIFICANT':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-red-950/60 border border-red-700/50 text-red-300">
            Significant
          </span>
        );
    }
  };

  const allMetrics: FeatureDriftResult[] = data
    ? Object.values(data.feature_metrics).sort((a, b) => b.psi - a.psi)
    : [];

  const filteredMetrics = allMetrics.filter((m) =>
    m.feature_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const displayedMetrics = showAllFeatures
    ? filteredMetrics
    : filteredMetrics.slice(0, 10);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-purple-400" />
              Production Feature Drift Monitor
            </h3>
            {data && getStatusBadge(data.summary.overall_drift_status)}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Empirical comparison of incoming network flow distributions against the verified CICIDS2017 training baseline.
          </p>
        </div>

        <button
          onClick={loadDriftData}
          disabled={loading}
          className="self-start sm:self-center flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Drift Window
        </button>
      </div>

      {/* Mandatory Disclaimer Box */}
      <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-800/40 text-xs text-purple-200 flex items-start gap-3">
        <Info className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed space-y-1">
          <div>
            <strong className="text-purple-100">Statistical Observability Notice: </strong>
            Feature drift measures statistical divergence from the benchmark training distribution (CICIDS2017) using operational PSI heuristics as an operational observability signal for model reliability. Distribution drift does NOT constitute evidence of malicious activity or an ongoing attack.
          </div>
          <div className="text-[11px] text-purple-300">
            When overall status is stable: <em>No substantial distribution shift was detected under the configured PSI threshold. Model performance was not assessed by this metric.</em>
          </div>
          <div className="text-[11px] text-purple-300/80">
            A low PSI does not prove model accuracy or confidence is maintained, and high PSI does not prove an attack is occurring. Drift monitoring does not measure prediction performance without suitable ground-truth labels.
          </div>
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && !data && (
        <div className="py-12 flex flex-col items-center justify-center text-slate-400 gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
          <span className="text-xs font-medium">Evaluating feature drift across flow buffer...</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/50 text-xs text-red-200 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {data && (
        <>
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Evaluated Flows
              </span>
              <span className="text-xl font-black text-slate-100 mt-1 block">
                {data.summary.evaluated_flow_count.toLocaleString()}
              </span>
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                {data.summary.is_sample_size_sufficient ? 'Sufficient sample (≥100)' : 'Sample < 100'}
              </span>
            </div>

            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Canonical Features
              </span>
              <span className="text-xl font-black text-slate-100 mt-1 block">
                {data.summary.evaluated_feature_count} / 48
              </span>
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                100% schema alignment
              </span>
            </div>

            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Mean PSI
              </span>
              <span className="text-xl font-black text-purple-300 mt-1 block">
                {data.summary.mean_psi.toFixed(4)}
              </span>
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Max: {data.summary.max_psi.toFixed(4)}
              </span>
            </div>

            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Shift Tally
              </span>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs font-bold text-emerald-400">
                  {data.summary.stable_feature_count}S
                </span>
                <span className="text-slate-600">/</span>
                <span className="text-xs font-bold text-amber-400">
                  {data.summary.moderate_feature_count}M
                </span>
                <span className="text-slate-600">/</span>
                <span className="text-xs font-bold text-red-400">
                  {data.summary.significant_feature_count}C
                </span>
              </div>
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Stable / Moderate / Significant
              </span>
            </div>
          </div>

          {/* Insufficient Sample Warning */}
          {!data.summary.is_sample_size_sufficient && (
            <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/40 text-xs text-amber-300 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <strong>Sample Size Caution: </strong>
                {data.summary.insufficient_sample_reason}
              </div>
            </div>
          )}

          {/* Table Header and Search */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  {showAllFeatures ? 'All 48 Evaluated Features' : 'Top Drifting Features (Ranked by PSI)'}
                </span>
                <span className="text-[11px] text-slate-500">
                  ({displayedMetrics.length} shown)
                </span>
              </div>

              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Filter feature name..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-8 pr-3 py-1 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500/50"
                  />
                </div>

                <button
                  onClick={() => setShowAllFeatures(!showAllFeatures)}
                  className="text-xs font-medium text-purple-400 hover:text-purple-300 transition"
                >
                  {showAllFeatures ? 'Show Top 10' : 'View All 48'}
                </button>
              </div>
            </div>

            {/* Metrics Table */}
            <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Feature Name</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">PSI</th>
                    <th className="py-2.5 px-3">SMD (Cohen's d)</th>
                    <th className="py-2.5 px-3">Baseline Mean ± Std</th>
                    <th className="py-2.5 px-3">Observed Mean ± Std</th>
                    <th className="py-2.5 px-3 text-right">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {displayedMetrics.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 font-sans text-xs">
                        No features matching the filter criteria.
                      </td>
                    </tr>
                  ) : (
                    displayedMetrics.map((feat) => (
                      <tr key={feat.feature_name} className="hover:bg-slate-800/30 transition">
                        <td className="py-2.5 px-3 font-semibold text-slate-200 font-sans">
                          {feat.feature_name}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 capitalize font-sans text-[11px]">
                          {feat.data_quality.bin_type.replace('_', ' ')}
                        </td>
                        <td className="py-2.5 px-3 font-bold text-slate-100">
                          {feat.psi.toFixed(4)}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {feat.smd !== null ? feat.smd.toFixed(4) : <span className="text-slate-600">N/A</span>}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                          {feat.baseline_mean.toFixed(2)} ± {feat.baseline_std.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 text-[10px]">
                          {feat.observed_mean.toFixed(2)} ± {feat.observed_std.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-sans">
                          {getSeverityBadge(feat.drift_severity)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
