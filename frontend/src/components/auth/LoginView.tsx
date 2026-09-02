import React, { useState } from 'react';
import {
  ShieldAlert,
  Lock,
  User as UserIcon,
  Eye,
  EyeOff,
  Loader2,
  ShieldCheck,
  AlertTriangle,
  Clock,
  KeyRound,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ApiError } from '../../api/client';

export const LoginView: React.FC = () => {
  const { login, sessionExpired, clearSessionExpired } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isRateLimited, setIsRateLimited] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please enter both username and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setIsRateLimited(false);
    clearSessionExpired();

    try {
      await login(username.trim(), password);
    } catch (err: any) {
      const apiErr = err as ApiError;
      if (apiErr.status === 429) {
        setIsRateLimited(true);
        setErrorMessage(apiErr.message || 'Too many failed login attempts. Access is throttled for 60 seconds.');
      } else if (apiErr.status === 401) {
        setErrorMessage('Authentication failed: Invalid username or password.');
      } else {
        setErrorMessage(apiErr.message || 'Authentication service offline. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-slate-950 flex flex-col justify-between relative overflow-hidden select-none">
      {/* Background Decorative Grid and Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(37,99,235,0.08),transparent_50%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(30,41,59,0.2)_1px,transparent_1px),linear-gradient(to_bottom,rgba(30,41,59,0.2)_1px,transparent_1px)] bg-[size:4rem_4rem] pointer-events-none opacity-40" />

      {/* Top Brand Bar */}
      <header className="px-6 py-4 flex items-center justify-between border-b border-slate-800/80 bg-slate-900/40 backdrop-blur-md relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <span className="font-bold text-slate-100 tracking-tight text-sm">NetSentinel</span>
            <span className="text-[10px] text-blue-400 font-mono ml-2 uppercase px-1.5 py-0.5 rounded bg-blue-950/80 border border-blue-800/40">
              v1.0-SOC
            </span>
          </div>
        </div>
        <div className="text-xs text-slate-400 font-mono hidden sm:flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>Restricted Defense Gateway</span>
        </div>
      </header>

      {/* Central Login Card */}
      <main className="flex-1 flex items-center justify-center p-4 sm:p-6 relative z-10">
        <div className="w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl backdrop-blur-xl relative">
          {/* Card Top Border Accent */}
          <div className="absolute top-0 left-6 right-6 h-0.5 bg-gradient-to-r from-transparent via-blue-500 to-transparent" />

          {/* Heading */}
          <div className="text-center mb-6">
            <div className="inline-flex p-3 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 mb-3">
              <KeyRound className="w-7 h-7" />
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">Security Operations Center</h2>
            <p className="text-xs text-slate-400 mt-1">Authenticate to access network flow telemetry &amp; live triage</p>
          </div>

          {/* Alerts / Notices */}
          {sessionExpired && !errorMessage && (
            <div
              role="alert"
              className="mb-5 p-3.5 rounded-xl bg-amber-950/50 border border-amber-800/50 text-amber-300 text-xs flex items-start gap-2.5 animate-fadeIn"
            >
              <Clock className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
              <div>
                <span className="font-semibold block">Session Timeout</span>
                <span>Your SOC session has expired. Please re-authenticate to continue.</span>
              </div>
            </div>
          )}

          {errorMessage && (
            <div
              role="alert"
              className={`mb-5 p-3.5 rounded-xl border text-xs flex items-start gap-2.5 animate-shake ${
                isRateLimited
                  ? 'bg-amber-950/60 border-amber-800/60 text-amber-300'
                  : 'bg-red-950/60 border-red-800/60 text-red-300'
              }`}
            >
              <AlertTriangle className={`w-4 h-4 shrink-0 mt-0.5 ${isRateLimited ? 'text-amber-400' : 'text-red-400'}`} />
              <div>
                <span className="font-semibold block">{isRateLimited ? 'Access Throttled' : 'Authentication Error'}</span>
                <span>{errorMessage}</span>
              </div>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            {/* Username Input */}
            <div>
              <label htmlFor="soc-username" className="block text-xs font-semibold text-slate-300 mb-1.5">
                Operator Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <UserIcon className="w-4 h-4" />
                </div>
                <input
                  id="soc-username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  autoFocus
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. soc_analyst"
                  disabled={isLoading}
                  className="w-full pl-10 pr-3.5 py-2.5 bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all font-mono disabled:opacity-50"
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label htmlFor="soc-password" className="block text-xs font-semibold text-slate-300 mb-1.5">
                Passphrase
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="soc-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••••••"
                  disabled={isLoading}
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all font-mono disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 transition-colors focus:outline-none"
                  tabIndex={0}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-600/20 transition-all duration-150 flex items-center justify-center gap-2 focus:outline-none focus:ring-2 focus:ring-blue-400 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Verifying Clearance...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-blue-200" />
                  <span>Sign In to SOC Portal</span>
                </>
              )}
            </button>
          </form>

          {/* Security Notice */}
          <div className="mt-6 pt-4 border-t border-slate-800/80 text-[11px] text-slate-400 text-center leading-relaxed">
            <span>Authorized defense personnel only. All access events, authentication attempts, and flow inspections are logged to an immutable audit record.</span>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="px-6 py-3 border-t border-slate-800/60 text-center text-[11px] text-slate-400 relative z-10 flex flex-col sm:flex-row justify-between items-center gap-1">
        <span>AI Network Anomaly Detection Platform • Defensive Capstone</span>
        <span>Session Expiration: 8 Hours (HttpOnly Signed Cookie)</span>
      </footer>
    </div>
  );
};
