import React from 'react';
import { Layers, ShieldCheck, AlertTriangle, Clock, Activity, FileCheck } from 'lucide-react';
import { PcapAnalysisSummary } from '../../types/pcap';
import { formatBytes, formatLatency } from '../../utils/formatters';

interface PcapSummaryCardsProps {
  summary: PcapAnalysisSummary;
}

export const PcapSummaryCards: React.FC<PcapSummaryCardsProps> = ({ summary }) => {
  const benignCount = summary.attack_distribution['BENIGN'] || 0;
  const attackCount = summary.analyzed_flows - benignCount;
  const criticalCount = summary.severity_distribution['CRITICAL'] || 0;
  const highCount = summary.severity_distribution['HIGH'] || 0;

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {/* 1. Analyzed Flows */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Analyzed Flows</span>
          <Layers className="w-4 h-4 text-blue-400" />
        </div>
        <div className="text-xl font-bold text-slate-100">
          {summary.analyzed_flows.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          of {summary.extracted_flows.toLocaleString()} extracted
        </div>
      </div>

      {/* 2. Benign / Normal */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Benign Flows</span>
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-xl font-bold text-emerald-400">
          {benignCount.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          {summary.analyzed_flows > 0 ? ((benignCount / summary.analyzed_flows) * 100).toFixed(1) : 0}% of traffic
        </div>
      </div>

      {/* 3. Attacks Detected */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Attacks Detected</span>
          <AlertTriangle className="w-4 h-4 text-red-400" />
        </div>
        <div className={`text-xl font-bold ${attackCount > 0 ? 'text-red-400' : 'text-slate-100'}`}>
          {attackCount.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          {criticalCount + highCount} high / critical
        </div>
      </div>

      {/* 4. Statistical Anomalies */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Anomalies</span>
          <Activity className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-xl font-bold text-amber-400">
          {summary.anomalies_flagged.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          Isolation Forest flag (α=0.01)
        </div>
      </div>

      {/* 5. Processing Time */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Latency</span>
          <Clock className="w-4 h-4 text-purple-400" />
        </div>
        <div className="text-xl font-bold text-slate-100">
          {formatLatency(summary.processing_time_ms)}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          {summary.analyzed_flows > 0 ? (summary.processing_time_ms / summary.analyzed_flows).toFixed(2) : 0} ms/flow
        </div>
      </div>

      {/* 6. File Metadata */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">File Size</span>
          <FileCheck className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-xl font-bold text-slate-100 truncate" title={summary.file_name}>
          {formatBytes(summary.file_size_bytes)}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5 truncate" title={summary.file_name}>
          {summary.file_name}
        </div>
      </div>
    </div>
  );
};
