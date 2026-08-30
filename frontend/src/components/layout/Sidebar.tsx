import React from 'react';
import {
  ShieldAlert,
  Sliders,
  Layers,
  FileCode2,
  Cpu,
  BarChart3,
  Terminal,
  Database,
  ExternalLink,
} from 'lucide-react';

export type TabId = 'overview' | 'single' | 'batch' | 'pcap' | 'models' | 'analytics';

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  const navItems = [
    { id: 'overview' as TabId, label: 'Security Overview', icon: <ShieldAlert className="w-4 h-4" />, badge: null },
    { id: 'single' as TabId, label: 'Single-Flow Analysis', icon: <Sliders className="w-4 h-4" />, badge: 'Live' },
    { id: 'batch' as TabId, label: 'Batch Flow Analysis', icon: <Layers className="w-4 h-4" />, badge: '5k Max' },
    { id: 'pcap' as TabId, label: 'PCAP File Analysis', icon: <FileCode2 className="w-4 h-4" />, badge: '10k Max' },
    { id: 'models' as TabId, label: 'Model Registry', icon: <Cpu className="w-4 h-4" />, badge: '16' },
    { id: 'analytics' as TabId, label: 'Session Analytics', icon: <BarChart3 className="w-4 h-4" />, badge: null },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950/80 flex flex-col justify-between shrink-0 h-[calc(100vh-4rem)] sticky top-16">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
          SOC Operations
        </div>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all duration-150 ${
                isActive
                  ? 'bg-blue-600/15 border border-blue-500/40 text-blue-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <span className={isActive ? 'text-blue-400' : 'text-slate-400'}>{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                    isActive
                      ? 'bg-blue-900/60 text-blue-300 border border-blue-700/50'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Info Card */}
      <div className="p-4 border-t border-slate-900 bg-slate-950/40">
        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
          <div className="flex items-center gap-2 text-slate-300 font-semibold mb-1">
            <Terminal className="w-3.5 h-3.5 text-amber-400" />
            <span>Operational Mode</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            In-Memory Session Engine. Ground-truth benchmark evaluation on CICIDS2017 flow telemetry.
          </p>
        </div>
      </div>
    </aside>
  );
};
