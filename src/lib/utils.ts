import { createCn } from "cn/config";

/**
 * Class merging that knows Sieve's type scale. Without this, the merger reads
 * `text-label` (a size from globals.css) as a colour, so `text-on-primary
 * text-label` lost the colour and the filled button rendered light text on
 * mint. Keep this list equal to the `--text-*` sizes in globals.css.
 */
export const TYPE_SCALE = ["display", "title-lg", "title", "kpi", "body", "body-strong", "label", "caption", "mono"] as const;

export const cn = createCn({
  extend: { classGroups: { "font-size": [{ text: [...TYPE_SCALE] }] } },
});
