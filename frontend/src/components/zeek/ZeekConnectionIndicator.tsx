import React from 'react';
import { Activity, Wifi, WifiOff, RefreshCw, AlertCircle } from 'lucide-react';
import { ZeekSSEConnectionState } from '../../types/zeek';

interface ZeekConnectionIndicatorProps {
  status: ZeekSSEConnectionState;
  onReconnect?: () => void;
  className?: string;
}

export const ZeekConnectionIndicator: React.FC<ZeekConnectionIndicatorProps> = ({
  status,
  onReconnect,
  className = '',
}) => {
  const getBadgeConfig = () => {
    switch (status) {
      case 'CONNECTED':
        return {
          icon: <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />,
          label: 'Live Stream Connected',
          style: 'bg-emerald-950/60 border-emerald-700/50 text-emerald-300',
        };
      case 'CONNECTING':
        return {
          icon: <RefreshCw className="w-3 h-3 animate-spin text-blue-400" />,
          label: 'Connecting...',
          style: 'bg-blue-950/60 border-blue-700/50 text-blue-300',
        };
      case 'RECONNECTING':
        return {
          icon: <RefreshCw className="w-3 h-3 animate-spin text-amber-400" />,
          label: 'Reconnecting...',
          style: 'bg-amber-950/60 border-amber-700/50 text-amber-300',
        };
      case 'DISABLED':
        return {
          icon: <AlertCircle className="w-3 h-3 text-slate-400" />,
          label: 'Spool Ingestion Disabled',
          style: 'bg-slate-900 border-slate-700 text-slate-400',
        };
      case 'DISCONNECTED':
      default:
        return {
          icon: <WifiOff className="w-3 h-3 text-red-400" />,
          label: 'Disconnected',
          style: 'bg-red-950/60 border-red-700/50 text-red-300',
        };
    }
  };

  const config = getBadgeConfig();

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-semibold shadow-sm transition-all ${config.style}`}>
        {config.icon}
        <span>{config.label}</span>
      </div>
      {(status === 'DISCONNECTED' || status === 'RECONNECTING') && onReconnect && (
        <button
          onClick={onReconnect}
          className="px-2.5 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition-colors"
        >
          Reconnect
        </button>
      )}
    </div>
  );
};
