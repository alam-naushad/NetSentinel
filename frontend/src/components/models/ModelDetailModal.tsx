import React from 'react';
import { ModelMetadata } from '../../types/models';
import { Modal } from '../common/Modal';
import { RoleBadge, TierBadge } from '../common/Badge';
import { formatBytes, formatNumber } from '../../utils/formatters';
import { Cpu, ShieldCheck, HardDrive, Hash, Layers } from 'lucide-react';

interface ModelDetailModalProps {
  model: ModelMetadata | null;
  onClose: () => void;
}

export const ModelDetailModal: React.FC<ModelDetailModalProps> = ({ model, onClose }) => {
  if (!model) return null;

  return (
    <Modal isOpen={!!model} onClose={onClose} title={`Model Artifact Provenance — ${model.model_key}`} maxWidth="3xl">
      <div className="space-y-5 text-xs">
        {/* Badges Bar */}
        <div className="flex flex-wrap items-center gap-2 pb-3 border-b border-slate-800">
          <RoleBadge role={model.model_role} />
          <TierBadge tier={model.deployment_tier} />
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
            Protocol: {model.protocol}
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
            Feature Set: {model.feature_set} ({model.n_features} features)
          </span>
        </div>

        {/* Key Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Training Rows</span>
            <p className="text-sm font-bold text-slate-100 font-mono mt-0.5">
              {model.training_rows ? formatNumber(model.training_rows) : 'N/A'}
            </p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Training Duration</span>
            <p className="text-sm font-bold text-slate-100 font-mono mt-0.5">
              {model.training_time_seconds ? `${model.training_time_seconds.toFixed(2)} s` : 'N/A'}
            </p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Disk Artifact Size</span>
            <p className="text-sm font-bold text-slate-100 font-mono mt-0.5">
              {formatBytes(model.artifact_size_bytes)}
            </p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">StandardScaler</span>
            <p className="text-sm font-bold font-mono mt-0.5 text-blue-400">
              {model.scaling_applied ? 'Active (Pre-fitted)' : 'None (Tree Native)'}
            </p>
          </div>
        </div>

        {/* SHA-256 Digest Box */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
          <div className="flex items-center gap-1.5 text-slate-400 font-semibold uppercase text-[10px]">
            <Hash className="w-3.5 h-3.5 text-blue-400" />
            <span>Cryptographic SHA-256 Checksum Integrity</span>
          </div>
          <div className="font-mono text-[11px] text-emerald-400 break-all select-all bg-slate-900/80 p-2 rounded border border-slate-800">
            {model.artifact_sha256}
          </div>
        </div>

        {/* Calibrated Thresholds if Anomaly Detector */}
        {model.thresholds && Object.keys(model.thresholds).length > 0 && (
          <div className="space-y-2">
            <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
              Calibrated Isolation Forest Anomaly Thresholds
            </span>
            <div className="grid grid-cols-2 gap-3">
              {Object.entries(model.thresholds).map(([alpha, val]) => (
                <div key={alpha} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                  <span className="text-slate-400">Constraint α = {alpha}:</span>
                  <span className="font-mono font-bold text-purple-300">{val.toFixed(6)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Class Vocabulary if Classifier */}
        {model.class_names && model.class_names.length > 0 && (
          <div className="space-y-2">
            <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
              Target Class Vocabulary ({model.class_names.length} Classes)
            </span>
            <div className="flex flex-wrap gap-1.5">
              {model.class_names.map((cls) => (
                <span key={cls} className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-medium">
                  {cls}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
