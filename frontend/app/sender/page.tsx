"use client";

import { useEffect } from "react";
import { useAuth } from "@/app/auth-context";
import { SenderDashboard } from "@/app/command-center";

export default function SenderPage() {
  const { user, role, loading, signOut } = useAuth();

  useEffect(() => {
    if (loading) return;
    if (!user) {
      window.location.href = "/login/sender";
      return;
    }
    if (role !== "sender") {
      window.location.href = "/login/sender";
      return;
    }
  }, [user, role, loading]);

  if (loading || !user || role !== "sender") {
    return (
      <div className="min-h-screen bg-sentinel-black flex items-center justify-center">
        <span className="text-sentinel-teal animate-pulse font-mono text-sm">LOADING…</span>
      </div>
    );
  }

  return <SenderDashboard onSignOut={signOut} />;
}
