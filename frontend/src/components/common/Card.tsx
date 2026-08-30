import React from 'react';

interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  headerAction?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  contentClassName?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  headerAction,
  children,
  className = '',
  contentClassName = '',
}) => {
  return (
    <div className={`bg-slate-900/80 border border-slate-800/90 rounded-xl shadow-lg backdrop-blur-sm overflow-hidden ${className}`}>
      {(title || subtitle || headerAction) && (
        <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between gap-4">
          <div>
            {title && <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className={`p-5 ${contentClassName}`}>{children}</div>
    </div>
  );
};
