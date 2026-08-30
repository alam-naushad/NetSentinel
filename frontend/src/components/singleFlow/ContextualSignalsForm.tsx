import React from 'react';
import { ShieldCheck, ShieldAlert, Zap } from 'lucide-react';
import { ContextualSignals } from '../../types/flows';

interface ContextualSignalsFormProps {
  context: ContextualSignals;
  onChange: (context: ContextualSignals) => void;
}

export const ContextualSignalsForm: React.FC<ContextualSignalsFormProps> = ({ context, onChange }) => {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Zap className="w-4 h-4 text-amber-400" />
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
          Operational Context Signals (Risk Modifiers)
        </h4>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* Sensitive Service Toggle */}
        <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 cursor-pointer hover:bg-slate-800/40 transition-colors">
          <input
            type="checkbox"
            checked={!!context.targets_sensitive_service}
            onChange={(e) => onChange({ ...context, targets_sensitive_service: e.target.checked })}
            className="mt-0.5 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-blue-500 w-4 h-4"
          />
          <div>
            <span className="font-semibold text-slate-200">Targets Critical / Sensitive Asset</span>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Elevates risk severity and score if attack or anomaly is confirmed.
            </p>
          </div>
        </label>

        {/* Repeated Source Incidents */}
        <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-slate-200">Repeated Source Incidents</span>
            <span className="font-mono text-blue-400 font-bold">{context.repeated_source_events || 0} events</span>
          </div>
          <input
            type="range"
            min="0"
            max="10"
            value={context.repeated_source_events || 0}
            onChange={(e) => onChange({ ...context, repeated_source_events: parseInt(e.target.value, 10) || 0 })}
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-blue-500"
          />
          <p className="text-[10px] text-slate-400">Contextual weight amplifier for recurring hostile IPs.</p>
        </div>
      </div>
    </div>
  );
};
