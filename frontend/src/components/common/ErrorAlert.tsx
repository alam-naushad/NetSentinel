import React from 'react';
import { AlertCircle, AlertTriangle } from 'lucide-react';
import { ApiError } from '../../api/client';

interface ErrorAlertProps {
  error: ApiError | Error | string | null;
  onDismiss?: () => void;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({ error, onDismiss }) => {
  if (!error) return null;

  const message = typeof error === 'string' ? error : error.message;
  const apiErr = typeof error === 'object' && 'missing_features' in error ? (error as ApiError) : null;

  return (
    <div className="bg-red-950/80 border border-red-700/60 rounded-xl p-4 text-red-200 shadow-md">
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1 text-sm">
          <p className="font-semibold text-red-100">API Error ({apiErr?.status ? `HTTP ${apiErr.status}` : 'Client Error'})</p>
          <p className="mt-1 text-red-300 whitespace-pre-wrap">{message}</p>
          
          {apiErr?.missing_features && apiErr.missing_features.length > 0 && (
            <div className="mt-3 bg-red-900/50 p-2.5 rounded-lg border border-red-800/60">
              <p className="text-xs font-semibold text-red-200 uppercase tracking-wider mb-1">
                Missing Required Features ({apiErr.missing_features.length}):
              </p>
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                {apiErr.missing_features.map((feat) => (
                  <span key={feat} className="text-xs px-2 py-0.5 rounded bg-red-950 text-red-300 font-mono border border-red-700/40">
                    {feat}
                  </span>
                ))}
              </div>
            </div>
          )}

          {apiErr?.invalid_fields && apiErr.invalid_fields.length > 0 && (
            <div className="mt-2 text-xs text-red-400">
              <span className="font-semibold">Invalid/Non-finite fields:</span> {apiErr.invalid_fields.join(', ')}
            </div>
          )}
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="text-red-400 hover:text-red-200 text-xs underline flex-shrink-0 ml-2"
          >
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
};
