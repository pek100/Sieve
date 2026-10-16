import { createCn } from "cn/config";

/**
 * Sieve type roles, as Tailwind font-size utilities (globals.css --text-*).
 * Class merging must know they are font sizes: unknown `text-*` names count
 * as colours, so `cn("text-label text-on-surface-muted")` would drop the size
 * and `text-on-primary` after `text-label` would drop the colour.
 */
export const TYPE_ROLES = ["display", "title-lg", "title", "kpi", "body", "body-strong", "label", "caption", "mono"] as const;

export const cn = createCn({
  extend: { classGroups: { "font-size": [{ text: [...TYPE_ROLES] }] } },
});
