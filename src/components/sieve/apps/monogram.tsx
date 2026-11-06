import { cn } from "@/lib/utils";

// Literal class names so Tailwind sees them. Order follows the chart series.
const TINTS = [
  "bg-series-1/16 text-series-1",
  "bg-series-2/16 text-series-2",
  "bg-series-3/16 text-series-3",
  "bg-series-4/16 text-series-4",
  "bg-series-5/16 text-series-5",
  "bg-series-6/16 text-series-6",
] as const;

/** Stable tint per app key, so an app keeps its colour between screens and sessions. */
function tintIndex(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return h % TINTS.length;
}

/** First letters of the first two words: "Google Chrome" -> "GC", "slack" -> "S". */
export function initials(name: string): string {
  const words = name.split(/[\s._-]+/).filter(Boolean);
  return (words.slice(0, 2).map((w) => w[0]).join("") || "?").toUpperCase();
}

/** The stand-in for an app's icon (AppIcon's fallback, while it loads or when the exe has none): a monogram on the app's tint. */
export function Monogram({ appKey, name, size = 32 }: { appKey: string; name: string; size?: 16 | 32 | 40 }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-sm font-semibold",
        size === 40 ? "size-10 text-body-strong" : size === 32 ? "size-8 text-label" : "size-4 rounded-xs text-caption",
        TINTS[tintIndex(appKey)],
      )}
    >
      {/* 16 px has room for one letter. */}
      {size === 16 ? initials(name).charAt(0) : initials(name)}
    </span>
  );
}
