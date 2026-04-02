import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5050';

interface User {
  id: string;
  email: string;
  role: string;
  twoFactorEnabled: boolean;
  isEmailVerified?: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string, twoFactorToken?: string) => Promise<any>;
  register: (email: string, password: string) => Promise<any>;
  logout: () => void;
  resetPassword: (email: string, hardToken: string, newPassword: string) => Promise<any>;
  refreshAccessToken: () => Promise<boolean>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Set axios Authorization header whenever token changes
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  }, [token]);

  // On mount: verify token via /profile, or try refresh if expired
  useEffect(() => {
    const initAuth = async () => {
      if (token) {
        try {
          const response = await axios.get(`${API_URL}/api/auth/profile`);
          setUser(response.data.user);
        } catch (error: any) {
          if (error.response?.status === 401) {
            const refreshed = await refreshAccessToken();
            if (!refreshed) clearAuth();
          } else {
            clearAuth();
          }
        }
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const clearAuth = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  // --- Refresh token ---
  const refreshAccessToken = async (): Promise<boolean> => {
    try {
      const response = await axios.post(
        `${API_URL}/api/auth/refresh`,
        {},
        { withCredentials: true }
      );
      const { accessToken, user: userData } = response.data;
      localStorage.setItem('token', accessToken);
      localStorage.setItem('user', JSON.stringify(userData));
      setToken(accessToken);
      setUser(userData);
      axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      return true;
    } catch {
      return false;
    }
  };

  // --- Login ---
  const login = async (email: string, password: string, twoFactorToken?: string) => {
    const response = await axios.post(
      `${API_URL}/api/auth/login`,
      { email, password, token: twoFactorToken },
      { withCredentials: true }
    );

    if (response.data.requiresTwoFactor) {
      return { requiresTwoFactor: true };
    }

    const { accessToken, user: userData } = response.data;
    localStorage.setItem('token', accessToken);
    localStorage.setItem('user', JSON.stringify(userData));
    setToken(accessToken);
    setUser(userData);
    return { success: true, user: userData };
  };

  // --- Register ---
  const register = async (email: string, password: string) => {
    const response = await axios.post(`${API_URL}/api/auth/register`, {
      email,
      password,
    });
    return response.data;
  };

  // --- Password reset via hard token ---
  const resetPassword = async (email: string, hardToken: string, newPassword: string) => {
    const response = await axios.post(`${API_URL}/api/auth/reset-password`, {
      email,
      hardToken,
      newPassword,
    });
    return response.data;
  };

  // --- Logout ---
  const logout = async () => {
    try {
      await axios.post(`${API_URL}/api/auth/logout`, {}, { withCredentials: true });
    } catch {
      // best-effort — clear client state regardless
    }
    clearAuth();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        login,
        register,
        logout,
        resetPassword,
        refreshAccessToken,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};