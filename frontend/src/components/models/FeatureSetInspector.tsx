import React, { useState } from 'react';
import { Layers, CheckCircle2, XCircle } from 'lucide-react';
import { FEATURE_FIELDS_METADATA } from '../../utils/featureMetadata';

export const FeatureSetInspector: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Feature Engineering Architecture (K=48 vs. K=47 Port Ablation)
          </h4>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Compare primary feature set vs. destination-port-ablated feature set used in Protocol A and B.
          </p>
        </div>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="text-xs text-blue-400 hover:text-blue-300 font-semibold"
        >
          {isOpen ? 'Hide Matrix' : 'Inspect Feature Matrix'}
        </button>
      </div>

      {isOpen && (
        <div className="max-h-80 overflow-y-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950 text-[10px] uppercase tracking-wider text-slate-400 border-b border-slate-800 sticky top-0">
              <tr>
                <th className="px-3 py-2">#</th>
                <th className="px-3 py-2 font-sans">Feature Name</th>
                <th className="px-3 py-2 font-sans">Category</th>
                <th className="px-3 py-2 text-center font-sans">Primary (K=48)</th>
                <th className="px-3 py-2 text-center font-sans">Port-Ablated (K=47)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {FEATURE_FIELDS_METADATA.map((f, idx) => {
                const isPort = f.key === 'destination_port';
                return (
                  <tr key={f.key} className="hover:bg-slate-800/40">
                    <td className="px-3 py-2 text-slate-500">{idx + 1}</td>
                    <td className="px-3 py-2 text-slate-200 font-semibold">{f.key}</td>
                    <td className="px-3 py-2 text-slate-400 font-sans">{f.category}</td>
                    <td className="px-3 py-2 text-center">
                      <span className="text-emerald-400 font-bold font-sans">Included</span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      {isPort ? (
                        <span className="text-red-400 font-bold font-sans">Ablated (Omitted)</span>
                      ) : (
                        <span className="text-emerald-400 font-bold font-sans">Included</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
