/** Sieve wordmark: a mesh mark (a ring over a 3x3 dot grid) and the name. Own artwork. */
export function Wordmark() {
  const dots = [-1, 0, 1].flatMap((y) => [-1, 0, 1].map((x) => ({ x: 12 + x * 4.5, y: 12 + y * 4.5 })));
  return (
    <span className="inline-flex items-center gap-2 text-title text-on-surface select-none">
      <span className="inline-flex size-8 items-center justify-center rounded-sm bg-mint-container text-on-mint-container">
        <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
          <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.75" />
          {dots.map((d) => (
            <circle key={`${d.x}-${d.y}`} cx={d.x} cy={d.y} r="1.4" fill="currentColor" />
          ))}
        </svg>
      </span>
      <span className="max-[480px]:sr-only">Sieve</span>
    </span>
  );
}
