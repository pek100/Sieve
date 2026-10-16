/**
 * Series slot -> token classes. Slot 1..6 are the --series-1..6 roles in
 * order (mint, lilac, peach, pink, cyan, yellow); slot 0 is Other. Class
 * names are spelled out so Tailwind sees them.
 */
export interface SeriesTone {
  fill: string;
  stroke: string;
  bg: string;
  /** The tint behind a monogram tile. */
  soft: string;
  text: string;
  border: string;
}

const TONES: Record<number, SeriesTone> = {
  0: { fill: "fill-series-other", stroke: "stroke-series-other", bg: "bg-series-other", soft: "bg-series-other/20", text: "text-series-other", border: "border-series-other" },
  1: { fill: "fill-series-1", stroke: "stroke-series-1", bg: "bg-series-1", soft: "bg-series-1/20", text: "text-series-1", border: "border-series-1" },
  2: { fill: "fill-series-2", stroke: "stroke-series-2", bg: "bg-series-2", soft: "bg-series-2/20", text: "text-series-2", border: "border-series-2" },
  3: { fill: "fill-series-3", stroke: "stroke-series-3", bg: "bg-series-3", soft: "bg-series-3/20", text: "text-series-3", border: "border-series-3" },
  4: { fill: "fill-series-4", stroke: "stroke-series-4", bg: "bg-series-4", soft: "bg-series-4/20", text: "text-series-4", border: "border-series-4" },
  5: { fill: "fill-series-5", stroke: "stroke-series-5", bg: "bg-series-5", soft: "bg-series-5/20", text: "text-series-5", border: "border-series-5" },
  6: { fill: "fill-series-6", stroke: "stroke-series-6", bg: "bg-series-6", soft: "bg-series-6/20", text: "text-series-6", border: "border-series-6" },
};

export function seriesTone(slot: number): SeriesTone {
  return TONES[slot] ?? TONES[0];
}
