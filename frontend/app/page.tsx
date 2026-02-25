"use client";

import { useEffect } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Shield, Send, Radio } from "lucide-react";
import { useAuth } from "@/app/auth-context";
import { cn } from "@/lib/utils";

export default function LandingPage() {
  const { user, role, loading } = useAuth();

  useEffect(() => {
    if (loading) return;
    if (user && role === "sender") window.location.href = "/sender";
    else if (user && role === "receiver") window.location.href = "/receiver";
  }, [user, role, loading]);

  if (loading) {
    return (
      <div className="min-h-screen bg-sentinel-black text-sentinel-text font-mono hex-bg flex items-center justify-center">
        <span className="text-sentinel-green animate-pulse">LOADING…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-sentinel-black text-sentinel-text font-mono hex-bg flex flex-col items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center max-w-2xl mx-auto"
      >
        <div className="flex items-center justify-center gap-3 mb-6">
          <Shield size={36} className="text-sentinel-green text-glow-green" />
          <h1 className="text-xl font-bold tracking-[0.25em] text-sentinel-green">
            PROJECT SENTINEL
          </h1>
        </div>
        <p className="text-sentinel-text-dim text-sm tracking-wide mb-2">
          Military-grade encrypted communication channel.
        </p>
        <p className="text-[11px] text-sentinel-text-dim/80 mb-10">
          Access is restricted to pre-provisioned operators. No self-registration. Use your assigned UUID and password to sign in.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <Link href="/login/sender">
            <motion.div
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className={cn(
                "border rounded-xl p-8 flex flex-col items-center gap-4",
                "border-sentinel-teal/40 bg-sentinel-surface hover:border-sentinel-teal/70",
                "hover:shadow-[0_0_30px_rgba(0,255,255,0.08)] transition-all"
              )}
            >
              <Send size={48} className="text-sentinel-teal" />
              <h2 className="text-sm font-bold tracking-[0.2em] text-sentinel-teal uppercase">
                Sender
              </h2>
              <p className="text-[11px] text-sentinel-text-dim text-center">
                Encrypt and transmit. Operator UUID + password required.
              </p>
              <span className="text-[10px] text-sentinel-teal/80 tracking-widest">
                Sign in as Sender →
              </span>
            </motion.div>
          </Link>

          <Link href="/login/receiver">
            <motion.div
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className={cn(
                "border rounded-xl p-8 flex flex-col items-center gap-4",
                "border-sentinel-green/40 bg-sentinel-surface hover:border-sentinel-green/70",
                "hover:shadow-[0_0_30px_rgba(0,255,65,0.08)] transition-all"
              )}
            >
              <Radio size={48} className="text-sentinel-green" />
              <h2 className="text-sm font-bold tracking-[0.2em] text-sentinel-green uppercase">
                Receiver
              </h2>
              <p className="text-[11px] text-sentinel-text-dim text-center">
                Monitor, decrypt, search. Operator UUID + password required.
              </p>
              <span className="text-[10px] text-sentinel-green/80 tracking-widest">
                Sign in as Receiver →
              </span>
            </motion.div>
          </Link>
        </div>

        <p className="mt-10 text-[9px] text-sentinel-text-dim tracking-widest">
          CLASSIFICATION: RESTRICTED · ACCOUNTS PRE-EXISTING · NO SELF-REGISTRATION
        </p>
      </motion.div>
    </div>
  );
}
