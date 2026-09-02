import React from 'react';
import { Activity, Shield, RefreshCw, Cpu, Database, CheckCircle2, AlertCircle, User, LogOut } from 'lucide-react';
import { useApp } from '../../context/useApp';
import { useAuth } from '../../context/AuthContext';

export const Header: React.FC = () => {
  const {
    backendConnected,
    serviceInfo,
    selectedSupervisedKey,
    selectedAnomalyKey,
    refreshHealth,
    refreshModels,
    isLoadingCatalog,
  } = useApp();
  const { user, logout } = useAuth();

  const handleRefresh = async () => {
    await Promise.all([refreshHealth(), refreshModels()]);
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-base font-bold tracking-tight text-slate-100 flex items-center gap-2">
            AI Network Anomaly Detection Platform
            <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800/50">
              SOC Hybrid Engine
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Defensive Multi-Class Attack Classification &amp; Statistical Anomaly Triage
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Active Models Pill */}
        <div className="hidden lg:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs">
          <div className="flex items-center gap-1.5 text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-slate-400">Supervised:</span>
            <span className="font-mono font-medium text-blue-300">{selectedSupervisedKey}</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5 text-slate-300">
            <Activity className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">Anomaly:</span>
            <span className="font-mono font-medium text-purple-300">{selectedAnomalyKey}</span>
          </div>
        </div>

        {/* Backend Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800">
          {backendConnected ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-semibold text-emerald-400">API Online</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-xs font-semibold text-red-400">API Offline</span>
            </>
          )}
        </div>

        {/* Refresh button */}
        <button
          onClick={handleRefresh}
          disabled={isLoadingCatalog}
          title="Refresh Backend Health & Catalog"
          className="p-2 rounded-lg border border-slate-800 bg-slate-950/60 text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isLoadingCatalog ? 'animate-spin text-blue-400' : ''}`} />
        </button>

        {/* Authenticated Operator Info & Logout */}
        {user && (
          <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-200">
              <User className="w-3.5 h-3.5 text-blue-400" />
              <span className="font-mono font-medium">{user.username}</span>
              <span className="text-[10px] uppercase font-bold text-slate-400 px-1 py-0.5 rounded bg-slate-800">
                {user.role}
              </span>
            </div>
            <button
              onClick={logout}
              title="Sign Out of SOC Session"
              className="p-2 rounded-lg border border-slate-800 bg-slate-950/60 text-slate-400 hover:text-red-400 hover:bg-red-950/30 hover:border-red-800/40 transition-colors cursor-pointer"
              aria-label="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
