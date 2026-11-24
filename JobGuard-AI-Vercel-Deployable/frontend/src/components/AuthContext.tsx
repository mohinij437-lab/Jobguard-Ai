import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { AuthUser } from "./AuthPanel";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  refreshSession: () => Promise<AuthUser | null>;
  setUser: (user: AuthUser | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUserState] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const setUser = useCallback((nextUser: AuthUser | null) => {
    setUserState(nextUser);
  }, []);

  const refreshSession = useCallback(async (): Promise<AuthUser | null> => {
    try {
      const response = await fetch("/api/auth/me", { credentials: "include" });
      if (!response.ok) {
        setUserState(null);
        return null;
      }
      const data = await response.json();
      const nextUser = data.user as AuthUser;
      setUserState(nextUser);
      return nextUser;
    } catch {
      setUserState(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const logout = useCallback(async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    } finally {
      setUserState(null);
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading, refreshSession, setUser, logout }),
    [user, loading, refreshSession, setUser, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextValue => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
};
