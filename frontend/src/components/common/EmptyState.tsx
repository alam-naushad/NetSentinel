import React from 'react';
import { ShieldCheck, Play, FolderOpen } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  actionText?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionText,
  onAction,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-2xl border-2 border-dashed border-slate-800 bg-slate-900/40">
      <div className="p-3.5 rounded-2xl bg-slate-800/60 border border-slate-700/50 text-slate-400 mb-4">
        {icon || <FolderOpen className="w-8 h-8 text-blue-400" />}
      </div>
      <h4 className="text-base font-semibold text-slate-200">{title}</h4>
      <p className="text-xs text-slate-400 mt-1 max-w-md">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition-colors"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          {actionText}
        </button>
      )}
    </div>
  );
};
