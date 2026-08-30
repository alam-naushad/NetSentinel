import React from 'react';
import { DetectionStatus, Severity, DeploymentTier, ModelRole } from '../../types/domain';

interface BadgeProps {
  status?: DetectionStatus | string;
  severity?: Severity | string;
  role?: ModelRole | string;
  tier?: DeploymentTier | string;
  children?: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<{ status: DetectionStatus | string; size?: 'sm' | 'md'; className?: string }> = ({
  status,
  size = 'md',
  className = '',
}) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';
  
  switch (status) {
    case 'NORMAL':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-emerald-950/70 border border-emerald-600/40 text-emerald-400 ${sizeClasses} ${className}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          NORMAL / BENIGN
        </span>
      );
    case 'UNKNOWN_ANOMALY':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-amber-950/70 border border-amber-600/50 text-amber-300 ${sizeClasses} ${className}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          UNKNOWN ANOMALY
        </span>
      );
    case 'KNOWN_ATTACK':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-red-950/80 border border-red-600/60 text-red-300 ${sizeClasses} ${className}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
          KNOWN ATTACK
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300 ${sizeClasses} ${className}`}>
          {status}
        </span>
      );
  }
};

export const SeverityBadge: React.FC<{ severity: Severity | string; size?: 'sm' | 'md' }> = ({
  severity,
  size = 'md',
}) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';
  
  switch (severity) {
    case 'LOW':
      return <span className={`inline-flex rounded-md bg-emerald-950/60 border border-emerald-700/40 text-emerald-300 ${sizeClasses}`}>LOW</span>;
    case 'MEDIUM':
      return <span className={`inline-flex rounded-md bg-amber-950/60 border border-amber-600/40 text-amber-300 ${sizeClasses}`}>MEDIUM</span>;
    case 'HIGH':
      return <span className={`inline-flex rounded-md bg-orange-950/70 border border-orange-600/50 text-orange-300 ${sizeClasses}`}>HIGH</span>;
    case 'CRITICAL':
      return <span className={`inline-flex rounded-md bg-red-950/90 border border-red-600/70 text-red-300 font-bold ${sizeClasses}`}>CRITICAL</span>;
    default:
      return <span className={`inline-flex rounded-md bg-slate-800 border border-slate-700 text-slate-300 ${sizeClasses}`}>{severity}</span>;
  }
};

export const RoleBadge: React.FC<{ role: ModelRole | string }> = ({ role }) => {
  if (role === 'SUPERVISED_CLASSIFIER') {
    return <span className="px-2 py-0.5 text-xs font-medium rounded bg-blue-950/60 border border-blue-600/40 text-blue-300">Supervised Classifier</span>;
  }
  return <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-950/60 border border-purple-600/40 text-purple-300">Statistical Anomaly Detector</span>;
};

export const TierBadge: React.FC<{ tier: DeploymentTier | string }> = ({ tier }) => {
  if (tier === 'PRODUCTION_DEFAULT') {
    return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 border border-emerald-500/50 text-emerald-300">Production Default</span>;
  }
  if (tier === 'PRODUCTION_ALTERNATIVE') {
    return <span className="px-2 py-0.5 text-xs font-medium rounded bg-cyan-900/50 border border-cyan-500/40 text-cyan-300">Production Alternative</span>;
  }
  return <span className="px-2 py-0.5 text-xs font-medium rounded bg-slate-800 border border-slate-600 text-slate-300">Research Evaluation</span>;
};
