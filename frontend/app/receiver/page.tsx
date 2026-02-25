"use client";

import { useEffect } from "react";
import { useAuth } from "@/app/auth-context";
import { ReceiverDashboard } from "@/app/command-center";

export default function ReceiverPage() {
  const { user, role, loading, signOut } = useAuth();

  useEffect(() => {
    if (loading) return;
    if (!user) {
      window.location.href = "/login/receiver";
      return;
    }
    if (role !== "receiver") {
      window.location.href = "/login/receiver";
      return;
    }
  }, [user, role, loading]);

  if (loading || !user || role !== "receiver") {
    return (
      <div className="min-h-screen bg-sentinel-black flex items-center justify-center">
        <span className="text-sentinel-green animate-pulse font-mono text-sm">LOADING…</span>
      </div>
    );
  }

  return <ReceiverDashboard onSignOut={signOut} />;
}
