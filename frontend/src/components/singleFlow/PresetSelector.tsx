import React from 'react';
import { Sparkles, Database, AlertTriangle, CheckCircle } from 'lucide-react';
import { FLOW_PRESETS, FlowPreset } from '../../utils/flowPresets';

interface PresetSelectorProps {
  selectedPresetId: string | null;
  onSelectPreset: (preset: FlowPreset) => void;
}

export const PresetSelector: React.FC<PresetSelectorProps> = ({
  selectedPresetId,
  onSelectPreset,
}) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-blue-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Authentic Dataset &amp; Scenario Presets
          </h4>
        </div>
        <span className="text-[11px] text-slate-400">1-Click Telemetry Preload</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {FLOW_PRESETS.map((preset) => {
          const isSelected = selectedPresetId === preset.id;
          const isAuthentic = preset.category === 'AUTHENTIC_DATASET';

          return (
            <button
              key={preset.id}
              onClick={() => onSelectPreset(preset)}
              className={`p-3 rounded-lg text-left transition-all border ${
                isSelected
                  ? 'bg-blue-950/60 border-blue-500 text-slate-100 shadow-md ring-1 ring-blue-500/50'
                  : 'bg-slate-950/60 border-slate-800/80 text-slate-300 hover:bg-slate-800/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-slate-100">{preset.name}</span>
                {isAuthentic ? (
                  <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-700/50">
                    Dataset Ground Truth
                  </span>
                ) : (
                  <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700/50">
                    Derived Demo Scenario
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                {preset.description}
              </p>
              <div className="mt-2 flex items-center justify-between text-[10px] text-slate-400 border-t border-slate-800/60 pt-1.5">
                <span>Class: <strong className="text-slate-300">{preset.expectedFamily}</strong></span>
                <span className="truncate max-w-[120px] text-slate-400">{preset.source}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
