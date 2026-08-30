import React from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
  accent?: 'blue' | 'emerald' | 'amber' | 'red' | 'purple';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon,
  accent = 'blue',
}) => {
  const accentBorder = {
    blue: 'border-l-blue-500 hover:border-blue-500/40',
    emerald: 'border-l-emerald-500 hover:border-emerald-500/40',
    amber: 'border-l-amber-500 hover:border-amber-500/40',
    red: 'border-l-red-500 hover:border-red-500/40',
    purple: 'border-l-purple-500 hover:border-purple-500/40',
  }[accent];

  const iconColor = {
    blue: 'text-blue-400 bg-blue-950/50 border-blue-800/40',
    emerald: 'text-emerald-400 bg-emerald-950/50 border-emerald-800/40',
    amber: 'text-amber-400 bg-amber-950/50 border-amber-800/40',
    red: 'text-red-400 bg-red-950/50 border-red-800/40',
    purple: 'text-purple-400 bg-purple-950/50 border-purple-800/40',
  }[accent];

  return (
    <div className={`bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm border-l-4 transition-all duration-200 ${accentBorder}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{label}</p>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-slate-100">{value}</span>
          </div>
          {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
        </div>
        {icon && <div className={`p-2.5 rounded-lg border ${iconColor}`}>{icon}</div>}
      </div>
    </div>
  );
};
