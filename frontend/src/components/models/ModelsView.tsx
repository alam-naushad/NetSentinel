import React, { useState } from 'react';
import { Cpu, Search, Filter, ShieldCheck, Check, Eye } from 'lucide-react';
import { useApp } from '../../context/useApp';
import { ModelMetadata } from '../../types/models';
import { formatBytes, formatNumber } from '../../utils/formatters';
import { RoleBadge, TierBadge } from '../common/Badge';
import { CardSkeleton } from '../common/LoadingState';
import { FeatureSetInspector } from './FeatureSetInspector';
import { ModelDetailModal } from './ModelDetailModal';

export const ModelsView: React.FC = () => {
  const {
    modelsCatalog,
    isLoadingCatalog,
    selectedSupervisedKey,
    selectedAnomalyKey,
    setSelectedSupervisedKey,
    setSelectedAnomalyKey,
  } = useApp();

  const [search, setSearch] = useState('');
  const [filterRole, setFilterRole] = useState('ALL');
  const [inspectModel, setInspectModel] = useState<ModelMetadata | null>(null);

  const models = modelsCatalog?.models || [];

  const filtered = models.filter((m) => {
    const matchRole = filterRole === 'ALL' || m.model_role === filterRole;
    const matchSearch =
      search === '' ||
      m.model_key.toLowerCase().includes(search.toLowerCase()) ||
      m.model_name.toLowerCase().includes(search.toLowerCase());
    return matchRole && matchSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <Cpu className="w-5 h-5 text-blue-400" />
            Model Registry &amp; Provenance Catalog
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Live catalog of 16 trained model artifacts across Protocol A &amp; B evaluation regimes.
          </p>
        </div>

        <div className="text-xs text-slate-400 bg-slate-900 border border-slate-800 px-3.5 py-2 rounded-xl">
          Catalog Inventory: <strong className="text-blue-400 font-mono">{models.length} artifacts</strong>
        </div>
      </div>

      {/* Feature Architecture Inspector */}
      <FeatureSetInspector />

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search model keys or architectures..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-slate-950 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="bg-slate-950 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:ring-1 focus:ring-blue-500"
            >
              <option value="ALL">All Roles</option>
              <option value="SUPERVISED_CLASSIFIER">Supervised Classifier</option>
              <option value="STATISTICAL_ANOMALY_DETECTOR">Anomaly Detector</option>
            </select>
          </div>
        </div>

        <div className="text-xs text-slate-400">
          Showing <strong className="text-slate-200">{filtered.length}</strong> of {models.length} models
        </div>
      </div>

      {/* Grid of Model Cards */}
      {isLoadingCatalog ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((model) => {
            const isDefaultSup = selectedSupervisedKey === model.model_key;
            const isDefaultAnom = selectedAnomalyKey === model.model_key;
            const isActiveInUI = isDefaultSup || isDefaultAnom;

            return (
              <div
                key={model.model_key}
                className={`bg-slate-900/90 border rounded-xl p-5 shadow-lg flex flex-col justify-between transition-all ${
                  isActiveInUI
                    ? 'border-blue-500/80 ring-1 ring-blue-500/40 bg-slate-900'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h4 className="text-sm font-bold text-slate-100 font-mono">{model.model_key}</h4>
                      <p className="text-xs text-blue-400 font-semibold">{model.model_name}</p>
                    </div>
                    <button
                      onClick={() => setInspectModel(model)}
                      className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                      title="Inspect Model Metadata & Checksum"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <RoleBadge role={model.model_role} />
                    <TierBadge tier={model.deployment_tier} />
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/80 font-mono">
                    <div>
                      <span className="text-slate-500">Protocol:</span>{' '}
                      <span className="text-slate-300 font-bold">{model.protocol}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Features:</span>{' '}
                      <span className="text-slate-300 font-bold">{model.feature_set} ({model.n_features})</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Size:</span>{' '}
                      <span className="text-slate-300">{formatBytes(model.artifact_size_bytes)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Rows:</span>{' '}
                      <span className="text-slate-300">{model.training_rows ? formatNumber(model.training_rows) : 'N/A'}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  {model.model_role === 'SUPERVISED_CLASSIFIER' ? (
                    <button
                      onClick={() => setSelectedSupervisedKey(model.model_key)}
                      className={`w-full py-1.5 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                        isDefaultSup
                          ? 'bg-blue-600 text-white shadow'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      {isDefaultSup ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>Active Classifier</span>
                        </>
                      ) : (
                        <span>Set as Active Classifier</span>
                      )}
                    </button>
                  ) : (
                    <button
                      onClick={() => setSelectedAnomalyKey(model.model_key)}
                      className={`w-full py-1.5 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                        isDefaultAnom
                          ? 'bg-purple-600 text-white shadow'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      {isDefaultAnom ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>Active Anomaly Detector</span>
                        </>
                      ) : (
                        <span>Set as Active Detector</span>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Inspection Modal */}
      <ModelDetailModal model={inspectModel} onClose={() => setInspectModel(null)} />
    </div>
  );
};
