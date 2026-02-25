"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import { Send } from "lucide-react";
import { useAuth } from "@/app/auth-context";
import { cn } from "@/lib/utils";

export default function SenderLoginPage() {
  const [uuid, setUuid] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { signIn, user, role } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (user && role === "sender") {
      router.replace("/sender");
    }
  }, [user, role, router]);

  if (user && role === "sender") {
    return (
      <div className="min-h-screen bg-sentinel-black flex items-center justify-center">
        <span className="text-sentinel-teal animate-pulse font-mono text-sm">REDIRECTING…</span>
      </div>
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { error: err } = await signIn(uuid, password, "sender");
      if (err) {
        setError(err.message);
        return;
      }
      router.replace("/sender");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-sentinel-black text-sentinel-text font-mono hex-bg flex flex-col items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-sm border border-sentinel-teal/40 rounded-xl bg-sentinel-surface p-8"
      >
        <div className="flex items-center gap-3 mb-6">
          <Send size={28} className="text-sentinel-teal" />
          <div>
            <h1 className="text-sm font-bold tracking-[0.2em] text-sentinel-teal uppercase">
              Sender — Operator Login
            </h1>
            <p className="text-[10px] text-sentinel-text-dim">Pre-provisioned credentials only</p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-[10px] text-sentinel-text-dim uppercase tracking-wider mb-1">
              Operator UUID
            </label>
            <input
              type="text"
              value={uuid}
              onChange={(e) => setUuid(e.target.value)}
              required
              className="w-full bg-sentinel-deep border border-sentinel-border rounded px-3 py-2 text-sm text-sentinel-green placeholder-sentinel-text-dim/50 focus:outline-none focus:border-sentinel-teal/50 font-mono"
              placeholder="550e8400-e29b-41d4-a716-446655440001"
            />
          </div>
          <div>
            <label className="block text-[10px] text-sentinel-text-dim uppercase tracking-wider mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-sentinel-deep border border-sentinel-border rounded px-3 py-2 text-sm text-sentinel-green placeholder-sentinel-text-dim/50 focus:outline-none focus:border-sentinel-teal/50"
              placeholder="••••••••"
            />
          </div>
          {error && (
            <p className="text-[11px] text-sentinel-red">{error}</p>
          )}
          <button
            type="submit"
            disabled={loading}
            className={cn(
              "w-full py-2.5 rounded text-xs font-semibold tracking-widest border transition-all",
              "border-sentinel-teal/50 text-sentinel-teal bg-sentinel-teal/10 hover:bg-sentinel-teal/20",
              "disabled:opacity-50 disabled:cursor-not-allowed"
            )}
          >
            {loading ? "VERIFYING…" : "SIGN IN"}
          </button>
        </form>

        <Link href="/" className="mt-6 inline-block text-[10px] text-sentinel-text-dim hover:text-sentinel-teal">
          ← Back to landing
        </Link>
      </motion.div>
    </div>
  );
}
