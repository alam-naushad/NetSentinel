import React, { createContext, useContext, useEffect, useState } from 'react';
import { authApi } from '../api/authApi';
import { AuthContextType, User } from '../types/auth';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);

  const checkAuth = async () => {
    try {
      const profile = await authApi.getMe();
      setUser(profile);
      setSessionExpired(false);
    } catch {
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();

    const handleUnauthorized = () => {
      setUser(null);
      setSessionExpired(true);
    };

    window.addEventListener('netsentinel:unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('netsentinel:unauthorized', handleUnauthorized);
    };
  }, []);

  const login = async (username: string, password: string): Promise<void> => {
    const profile = await authApi.login({ username, password });
    setUser(profile);
    setSessionExpired(false);
  };

  const logout = async (): Promise<void> => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
      setSessionExpired(false);
    }
  };

  const clearSessionExpired = () => {
    setSessionExpired(false);
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: Boolean(user),
    isLoading,
    sessionExpired,
    login,
    logout,
    clearSessionExpired,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
