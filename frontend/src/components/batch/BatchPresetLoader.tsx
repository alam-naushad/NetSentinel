import React from 'react';
import { Upload, FileCode, CheckCircle, Database } from 'lucide-react';
import { FlowFeaturesInput } from '../../types/flows';
import { FLOW_PRESETS } from '../../utils/flowPresets';

interface BatchPresetLoaderProps {
  onLoadBatch: (flows: FlowFeaturesInput[], label: string) => void;
  isLoading: boolean;
}

export const BatchPresetLoader: React.FC<BatchPresetLoaderProps> = ({ onLoadBatch, isLoading }) => {
  const loadCanonical4Batch = () => {
    const flows = FLOW_PRESETS.slice(0, 4).map((p) => p.flow);
    onLoadBatch(flows, '4-Flow Authentic Dataset Benchmark (BENIGN, DOS, DDOS, PORT_SCAN)');
  };

  const loadSynthetic20Batch = () => {
    // 20 realistic flows combining all authentic presets repeated with subtle variations
    const flows: FlowFeaturesInput[] = [];
    for (let i = 0; i < 5; i++) {
      FLOW_PRESETS.forEach((p) => {
        flows.push({
          ...p.flow,
          flow_bytes_per_sec: p.flow.flow_bytes_per_sec * (1 + (i * 0.05)),
          fwd_packets_per_sec: p.flow.fwd_packets_per_sec * (1 + (i * 0.02)),
        });
      });
    }
    onLoadBatch(flows, '25-Flow Mixed Benchmark Dataset Batch');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const parsed = JSON.parse(text);
        const flowsArray: FlowFeaturesInput[] = Array.isArray(parsed) ? parsed : parsed.flows;
        if (Array.isArray(flowsArray) && flowsArray.length > 0) {
          onLoadBatch(flowsArray.slice(0, 5000), `Uploaded JSON File: ${file.name} (${flowsArray.length} flows)`);
        } else {
          alert('Invalid JSON: expected an array of flow feature objects or { flows: [...] }');
        }
      } catch (err: any) {
        alert(`Failed to parse JSON file: ${err.message}`);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-blue-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Batch Telemetry Preload &amp; File Ingestion
          </h4>
        </div>
        <span className="text-[11px] text-slate-400">Vectorized Batch Engine (Up to 5,000 flows)</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <button
          onClick={loadCanonical4Batch}
          disabled={isLoading}
          className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-blue-500/50 hover:bg-slate-800/60 text-left transition-all group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-slate-100 group-hover:text-blue-300">4-Flow Benchmark</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              Verified
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Exact authentic dataset fixtures: Benign, DoS, DDoS, and PortScan.
          </p>
        </button>

        <button
          onClick={loadSynthetic20Batch}
          disabled={isLoading}
          className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-purple-500/50 hover:bg-slate-800/60 text-left transition-all group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-slate-100 group-hover:text-purple-300">25-Flow Multi-Traffic</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
              Mixed Batch
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            High-density composite flow stream covering multi-class attack patterns.
          </p>
        </button>

        {/* Custom Upload Zone */}
        <label className="p-3.5 rounded-xl bg-slate-950 border border-dashed border-slate-700 hover:border-blue-500/80 hover:bg-slate-800/40 text-left transition-all cursor-pointer flex flex-col justify-center">
          <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" disabled={isLoading} />
          <div className="flex items-center gap-2 mb-1">
            <Upload className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs font-bold text-slate-200">Upload JSON Flows</span>
          </div>
          <p className="text-[11px] text-slate-400">Upload custom array of 48-feature flow telemetry JSON.</p>
        </label>
      </div>
    </div>
  );
};
