import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "./auth-context";

export const metadata: Metadata = {
  title: "Project Sentinel - Zero-Exposure Threat Detection",
  description:
    "Military-grade encrypted communications threat detection system. " +
    "Powered by Searchable Symmetric Encryption and Bloom Filters.",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-sentinel-black min-h-screen antialiased">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
