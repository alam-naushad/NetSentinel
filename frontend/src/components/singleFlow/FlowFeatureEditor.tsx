import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Sliders, Check } from 'lucide-react';
import { FlowFeaturesInput } from '../../types/flows';
import { FEATURE_CATEGORIES, FEATURE_FIELDS_METADATA } from '../../utils/featureMetadata';

interface FlowFeatureEditorProps {
  features: FlowFeaturesInput;
  onChange: (key: keyof FlowFeaturesInput, value: number) => void;
}

export const FlowFeatureEditor: React.FC<FlowFeatureEditorProps> = ({ features, onChange }) => {
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({
    network_ids: true,
    traffic_rates: true,
    packet_lengths: false,
    tcp_flags: false,
    iat_timings: false,
    headers_windows: false,
    active_idle: false,
  });

  const toggleCategory = (catId: string) => {
    setOpenCategories((prev) => ({ ...prev, [catId]: !prev[catId] }));
  };

  return (
    <div className="space-y-3">
      {FEATURE_CATEGORIES.map((cat) => {
        const isOpen = openCategories[cat.id];
        const fields = FEATURE_FIELDS_METADATA.filter((f) => f.category === cat.id);

        return (
          <div
            key={cat.id}
            className="border border-slate-800 bg-slate-900/60 rounded-xl overflow-hidden transition-colors"
          >
            <button
              onClick={() => toggleCategory(cat.id)}
              className="w-full px-4 py-3 bg-slate-900/90 flex items-center justify-between text-left hover:bg-slate-800/80 transition-colors"
            >
              <div className="flex items-center gap-2">
                {isOpen ? <ChevronDown className="w-4 h-4 text-blue-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">{cat.label}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                  {fields.length} features
                </span>
              </div>
              <span className="text-[11px] text-slate-500">{isOpen ? 'Collapse' : 'Expand'}</span>
            </button>

            {isOpen && (
              <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 bg-slate-950/40 border-t border-slate-800/60">
                {fields.map((field) => {
                  const val = features[field.key];
                  return (
                    <div key={field.key} className="space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <label htmlFor={field.key} className="font-medium text-slate-300 truncate" title={field.description}>
                          {field.label}
                        </label>
                        {field.unit && <span className="text-slate-500 text-[10px] font-mono">{field.unit}</span>}
                      </div>
                      <input
                        id={field.key}
                        type="number"
                        step="any"
                        value={val}
                        onChange={(e) => onChange(field.key, parseFloat(e.target.value) || 0)}
                        className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
