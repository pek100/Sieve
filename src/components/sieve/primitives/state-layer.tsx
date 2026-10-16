"use client";

import { useEffect, useRef } from "react";

/**
 * Material state layer plus ripple, the one implementation every pressable
 * uses. Render it as the LAST child of a `relative overflow-hidden` element.
 * Hover, focus and pressed opacities come from CSS (globals.css, tokens
 * --state-*); this component only adds the ripple from the pointer origin.
 * Under prefers-reduced-motion the ripple is not spawned at all.
 */
export function StateLayer() {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const layer = ref.current;
    const host = layer?.parentElement;
    if (!layer || !host) return;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)");

    const onDown = (e: PointerEvent) => {
      if (reduce?.matches) return;
      if (host.matches(":disabled, [data-disabled], [aria-disabled='true']")) return;
      const rect = host.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const r = Math.hypot(Math.max(x, rect.width - x), Math.max(y, rect.height - y));
      const ripple = document.createElement("span");
      ripple.dataset.ripple = "";
      ripple.style.left = `${x - r}px`;
      ripple.style.top = `${y - r}px`;
      ripple.style.width = ripple.style.height = `${r * 2}px`;
      layer.appendChild(ripple);
      ripple.addEventListener("animationend", (ev) => {
        if (ev.animationName === "ripple-fade") ripple.remove();
      });
    };

    host.addEventListener("pointerdown", onDown);
    return () => host.removeEventListener("pointerdown", onDown);
  }, []);

  return <span ref={ref} data-state-layer="" aria-hidden="true" />;
}
