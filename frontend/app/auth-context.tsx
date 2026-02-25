"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";

const AUTH_STORAGE_KEY = "sentinel_auth";

export type AuthRole = "sender" | "receiver" | null;

interface StoredAuth {
  access_token: string;
  role: AuthRole;
  exp: number;
}

interface AuthState {
  user: { uuid: string } | null;
  role: AuthRole;
  loading: boolean;
  signIn: (uuid: string, password: string, requestedRole: AuthRole) => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

function getApiUrl(): string {
  return typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
    : "http://localhost:8000";
}

function parseJwtPayload(token: string): { sub?: string; role?: string; exp?: number } | null {
  try {
    const base64 = token.split(".")[1];
    if (!base64) return null;
    const json = atob(base64.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json) as { sub?: string; role?: string; exp?: number };
  } catch {
    return null;
  }
}

function loadStoredAuth(): StoredAuth | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) return null;
  try {
    const data = JSON.parse(raw) as StoredAuth;
    if (!data.access_token || !data.role) return null;
    const payload = parseJwtPayload(data.access_token);
    if (!payload || !payload.exp) return null;
    if (payload.exp * 1000 < Date.now()) {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

function clearStoredAuth(): void {
  if (typeof window !== "undefined") localStorage.removeItem(AUTH_STORAGE_KEY);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [stored, setStored] = useState<StoredAuth | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    setStored(loadStoredAuth());
    setLoading(false);
  }, []);

  const role: AuthRole =
    stored?.role === "sender" ? "sender" : stored?.role === "receiver" ? "receiver" : null;

  const user = stored && role ? { uuid: parseJwtPayload(stored.access_token)?.sub ?? "" } : null;

  const signIn = useCallback(
    async (uuid: string, password: string, requestedRole: AuthRole) => {
      const apiUrl = getApiUrl();
      try {
        const res = await fetch(`${apiUrl}/api/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ uuid: uuid.trim(), password }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          return { error: new Error(data.detail ?? "Login failed") };
        }
        if (requestedRole && data.role !== requestedRole) {
          return {
            error: new Error(
              `This operator is registered as ${data.role}. Use the ${data.role} login.`
            ),
          };
        }
        const payload = parseJwtPayload(data.access_token);
        const auth: StoredAuth = {
          access_token: data.access_token,
          role: data.role === "sender" ? "sender" : data.role === "receiver" ? "receiver" : null,
          exp: payload?.exp ?? Math.floor(Date.now() / 1000) + 86400,
        };
        if (typeof window !== "undefined") {
          localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
        }
        setStored(auth);
        return { error: null };
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Network error";
        const isNetwork = /failed to fetch|network error|load failed/i.test(msg);
        return {
          error: new Error(
            isNetwork
              ? "Cannot reach the API. Start the backend: cd backend && python main.py (port 8000)"
              : msg
          ),
        };
      }
    },
    []
  );

  const signOut = useCallback(async () => {
    clearStoredAuth();
    setStored(null);
    router.push("/");
  }, [router]);

  return (
    <AuthContext.Provider
      value={{
        user,
        role,
        loading,
        signIn,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
