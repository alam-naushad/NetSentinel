import React, { useState } from 'react';
import {
  ShieldAlert,
  Info,
  ChevronDown,
  ChevronUp,
  FileCheck,
  AlertCircle,
  Hash,
} from 'lucide-react';
import { ZeekAnalysisSummary } from '../../types/zeek';

interface ZeekCompletenessPanelProps {
  summary: ZeekAnalysisSummary;
}

export const ZeekCompletenessPanel: React.FC<ZeekCompletenessPanelProps> = ({ summary }) => {
  const [isFeaturesExpanded, setIsFeaturesExpanded] = useState(false);

  const report = summary.completeness_report;

  // Fallback: If no completeness report is present, preserve the existing static banner
  if (!report) {
    return (
      <div className="flex items-start gap-3 p-3.5 bg-blue-950/40 border border-blue-800/40 rounded-xl text-blue-300 text-xs">
        <Info className="w-4 h-4 shrink-0 mt-0.5 text-blue-400" />
        <div className="space-y-0.5">
          <p className="font-semibold text-blue-200">Telemetry Only — ML Classification Not Performed</p>
          <p className="text-blue-300/80 leading-relaxed">
            This view displays native Zeek connection metadata. No attack classification, risk score, or anomaly detection has been applied to these connections.
          </p>
        </div>
      </div>
    );
  }

  const comp = report.completeness;
  const sampleId = report.sample_record_identifier || report.flow_id || 'first_record';
  const totalConns = summary.total_connections_parsed ?? 0;
  const validCount = comp.valid_features_count ?? 0;
  const totalRequired = comp.total_required_features ?? 48;
  const completenessPct = ((comp.completeness_score ?? 0) * 100).toFixed(1);
  const missingCount = comp.missing_features?.length ?? 0;
  const invalidEntries = Object.entries(comp.invalid_features || {});
  const invalidCount = invalidEntries.length;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
      {/* 1. Header & Primary Status */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/70 pb-3.5">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-blue-950/60 border border-blue-800/50 text-blue-400 shrink-0 mt-0.5">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-bold text-slate-100 tracking-wide">
                Routing Decision: {report.route}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-700/50 uppercase tracking-wider">
                {report.route}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                {report.source_channel}
              </span>
            </div>
            <p className="text-xs text-blue-300/90 mt-1 font-medium leading-relaxed">
              ML inference: Not performed — native Zeek connection telemetry is not validated as compatible with the frozen CICFlowMeter schema.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Sample-Level Audit Disclaimer Notice */}
      <div className="flex items-start gap-2.5 p-2.5 bg-slate-950/60 border border-slate-800/80 rounded-lg text-slate-300 text-xs">
        <Info className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
        <div className="leading-relaxed">
          <span className="font-semibold text-cyan-300 uppercase tracking-wider text-[11px] mr-1.5">
            Sample-Level Audit:
          </span>
          Evaluated on representative connection UID{' '}
          <span className="font-mono text-cyan-200 bg-cyan-950/50 px-1.5 py-0.5 rounded border border-cyan-800/40">
            {sampleId}
          </span>{' '}
          ({totalConns.toLocaleString()} total connections in file). The canonical schema requires {totalRequired} flow features; this connection record contains {validCount} valid matching features, yielding a sample-level completeness result of {validCount}/{totalRequired} ({completenessPct}%). Feature metrics reflect individual record schema completeness, not a file-wide aggregate.
        </div>
      </div>

      {/* 3. Metric Badges Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
        <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Completeness</span>
            <FileCheck className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-lg font-bold text-slate-100 mt-1">
            {completenessPct}%
          </div>
          <div className="text-[10px] text-slate-400">
            {validCount} / {totalRequired} valid features matching schema
          </div>
        </div>

        <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Missing Features</span>
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-lg font-bold text-amber-400 mt-1">
            {missingCount}
          </div>
          <div className="text-[10px] text-slate-400">
            {missingCount} required features missing from this sample record
          </div>
        </div>

        <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Invalid Features</span>
            <Hash className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-lg font-bold text-slate-100 mt-1">
            {invalidCount}
          </div>
          <div className="text-[10px] text-slate-400">
            {invalidCount === 0 ? 'Zero rejected values' : 'Failed validation'}
          </div>
        </div>

        <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
            Dual-Gate Result
          </div>
          <div className="text-sm font-bold text-amber-300 mt-1.5 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400 inline-block animate-pulse" />
            Bypassed (Safe)
          </div>
          <div className="text-[10px] text-slate-400">
            Gate 1 &amp; Gate 2 protected
          </div>
        </div>
      </div>

      {/* 4. Routing Reason Text */}
      <div className="bg-slate-950/40 border border-slate-800/60 rounded-lg p-3 text-xs text-slate-300 space-y-1">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
          Routing Explanation:
        </span>
        <p className="font-mono text-slate-300/90 leading-relaxed text-[11px]">
          {report.routing_reason}
        </p>
      </div>

      {/* 5. Collapsible Missing & Invalid Features List */}
      <div className="border-t border-slate-800/60 pt-3">
        <button
          onClick={() => setIsFeaturesExpanded(!isFeaturesExpanded)}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800 text-xs text-slate-300 font-medium transition-colors"
        >
          <span className="flex items-center gap-2">
            <span>Schema Audit Details:</span>
            <span className="text-amber-400 font-mono font-semibold">
              {missingCount} required features missing
            </span>
            {invalidCount > 0 && (
              <span className="text-rose-400 font-mono font-semibold">
                • {invalidCount} invalid
              </span>
            )}
          </span>
          {isFeaturesExpanded ? (
            <ChevronUp className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </button>

        {isFeaturesExpanded && (
          <div className="mt-2.5 p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-3 animate-in fade-in duration-150">
            {/* Missing Features */}
            {missingCount > 0 && (
              <div>
                <p className="text-[11px] font-semibold text-slate-400 mb-2 uppercase tracking-wider">
                  Required Canonical Features Missing From Sample Record ({missingCount} / {totalRequired}):
                </p>
                <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto pr-1">
                  {comp.missing_features.map((feat) => (
                    <span
                      key={feat}
                      className="px-2 py-0.5 text-[11px] font-mono bg-slate-900 border border-slate-800 text-slate-400 rounded"
                    >
                      {feat}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Invalid Features (if any) */}
            {invalidCount > 0 && (
              <div className="border-t border-slate-800/60 pt-2.5">
                <p className="text-[11px] font-semibold text-rose-400 mb-2 uppercase tracking-wider">
                  Invalid Value Reasons ({invalidCount}):
                </p>
                <div className="space-y-1 text-[11px] font-mono">
                  {invalidEntries.map(([feat, reason]) => (
                    <div
                      key={feat}
                      className="p-1.5 rounded bg-rose-950/30 border border-rose-900/40 text-rose-300 flex justify-between"
                    >
                      <span className="font-semibold">{feat}</span>
                      <span className="text-rose-400/80">{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
