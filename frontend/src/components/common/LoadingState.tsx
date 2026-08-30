import React from 'react';
import { Loader2 } from 'lucide-react';

export const LoadingSpinner: React.FC<{ message?: string; size?: 'sm' | 'md' | 'lg' }> = ({
  message = 'Loading...',
  size = 'md',
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-10 h-10',
  }[size];

  return (
    <div className="flex flex-col items-center justify-center p-8 gap-3 text-slate-400">
      <Loader2 className={`${sizeClasses} animate-spin text-blue-500`} />
      {message && <p className="text-xs font-medium text-slate-400 animate-pulse">{message}</p>}
    </div>
  );
};

export const CardSkeleton: React.FC = () => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 animate-pulse">
    <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
    <div className="h-8 bg-slate-800/60 rounded w-1/2 mb-2" />
    <div className="h-3 bg-slate-800/40 rounded w-2/3" />
  </div>
);
