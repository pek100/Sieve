/**
 * Hour x weekday heatmap (pure). Folds hourly activity buckets from
 * source.history() into a 7 x 24 grid in local time, Monday first, and
 * assigns each cell one of HEAT_STEPS steps. A cell's value is the mean
 * activity of its hours, so a weekday seen twice is not twice as hot.
 */
/** Shape of a source HourBucket (core may not import the data seam). */
export interface HourActivity {
  /** Start of the hour, epoch ms. */
  t: number;
  flows: number;
}

export const HEAT_STEPS = 4;
export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export interface HeatCell {
  /** 0 = Monday. */
  day: number;
  hour: number;
  /** Mean flows per hour bucket in this cell; 0 when no hour was seen. */
  value: number;
  /** Hour buckets folded into this cell. */
  hours: number;
  /** 0 (nothing) to HEAT_STEPS - 1 (busiest third). */
  step: number;
}

export interface HeatGrid {
  /** Row-major: day 0 hours 0..23, then day 1, ... */
  cells: HeatCell[];
  max: number;
  /** Hour buckets seen in total. */
  hours: number;
}

/** Step for a value against the grid maximum: 0 for nothing, then thirds of the max. */
export function heatStep(value: number, max: number): number {
  if (value <= 0 || max <= 0) return 0;
  const top = HEAT_STEPS - 1;
  return 1 + Math.min(top - 1, Math.floor((top * value) / max));
}

export function heatGrid(buckets: readonly HourActivity[]): HeatGrid {
  const sums = new Array<number>(7 * 24).fill(0);
  const counts = new Array<number>(7 * 24).fill(0);
  for (const b of buckets) {
    const d = new Date(b.t);
    const i = ((d.getDay() + 6) % 7) * 24 + d.getHours();
    sums[i] += b.flows;
    counts[i] += 1;
  }
  const values = sums.map((s, i) => (counts[i] ? s / counts[i] : 0));
  const max = Math.max(0, ...values);
  const cells = values.map((value, i) => ({
    day: Math.floor(i / 24),
    hour: i % 24,
    value,
    hours: counts[i],
    step: heatStep(value, max),
  }));
  return { cells, max, hours: buckets.length };
}
