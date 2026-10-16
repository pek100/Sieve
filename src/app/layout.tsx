import type { Metadata, Viewport } from "next";
import { AppShell } from "@/components/sieve/shell/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sieve",
  description: "See which apps on this computer are talking to the network.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning className="h-full antialiased">
      <body className="min-h-full">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
