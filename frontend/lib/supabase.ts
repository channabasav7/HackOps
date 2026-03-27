import { createClient } from "@supabase/supabase-js";

const rawSupabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();

// Supabase is optional in local/offline mode.
// We use it only as a fallback realtime channel if WebSocket delivery is missed.
if (!rawSupabaseUrl || !supabaseAnonKey) {
  // eslint-disable-next-line no-console
  console.warn(
    "[sentinel] Supabase env vars missing; realtime fallback disabled. " +
      "Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to enable it."
  );
}

// Guard against common placeholder mistakes like [YOUR-PROJECT-REF].
if (
  rawSupabaseUrl &&
  (rawSupabaseUrl.includes("[") ||
    rawSupabaseUrl.includes("]") ||
    rawSupabaseUrl.includes("YOUR-PROJECT-REF"))
) {
  throw new Error(
    "Invalid NEXT_PUBLIC_SUPABASE_URL: placeholder value detected. " +
      "Use your real Supabase project URL, e.g. https://abcxyzcompany.supabase.co"
  );
}

let supabaseUrl: string;
try {
  if (!rawSupabaseUrl) throw new Error("missing");
  const parsed = new URL(rawSupabaseUrl);
  if (parsed.protocol !== "https:") {
    throw new Error("Supabase URL must start with https://");
  }
  supabaseUrl = parsed.toString().replace(/\/$/, "");
} catch {
  supabaseUrl = "";
}

export const supabase =
  supabaseUrl && supabaseAnonKey
    ? createClient(supabaseUrl, supabaseAnonKey, {
        realtime: {
          params: { eventsPerSecond: 20 },
        },
      })
    : null;
