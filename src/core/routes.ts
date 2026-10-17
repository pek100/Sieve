/**
 * The navigation list. The top bar renders exactly these, in this order.
 * Only routes that exist are listed; a slice that adds a screen appends one entry.
 * `icon` names a lucide-react icon resolved in the shell (core stays React free).
 */
export interface RouteDef {
  href: string;
  label: string;
  icon: "activity" | "app-window" | "list" | "settings";
}

export const ROUTES: readonly RouteDef[] = [
  { href: "/", label: "Home", icon: "activity" },
  { href: "/apps", label: "Apps", icon: "app-window" },
  { href: "/settings", label: "Settings", icon: "settings" },
];

/** Which route a pathname belongs to (static export uses trailing slashes). */
export function activeRoute(pathname: string): RouteDef | undefined {
  const norm = (p: string) => (p.length > 1 ? p.replace(/\/+$/, "") : p);
  const path = norm(pathname);
  return [...ROUTES]
    .sort((a, b) => b.href.length - a.href.length)
    .find((r) => (r.href === "/" ? path === "/" : path === norm(r.href) || path.startsWith(norm(r.href) + "/")));
}
