"use client"

import * as React from "react"
import { cn } from "cn"
import { Switch as SwitchPrimitive } from "radix-ui"

// Sieve: Material 3 style switch. Track 44x24 (sm 36x20), thumb grows when on.
// Off: outlined track, muted thumb. On: mint track, dark thumb.
function Switch({
  className,
  size = "default",
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root> & {
  size?: "sm" | "default"
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch relative inline-flex shrink-0 items-center rounded-full border-2 transition-[background-color,border-color,box-shadow] duration-(--motion-base) ease-standard outline-none after:absolute after:-inset-x-3 after:-inset-y-2 data-[size=default]:h-6 data-[size=default]:w-11 data-[size=sm]:h-5 data-[size=sm]:w-9 data-checked:border-primary data-checked:bg-primary data-unchecked:border-outline-strong data-unchecked:bg-surface-3 data-disabled:cursor-not-allowed data-disabled:opacity-(--disabled-content) aria-invalid:border-blocked",
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block rounded-full transition-[transform,width,height,background-color] duration-(--motion-base) ease-standard data-unchecked:bg-on-surface-muted data-checked:bg-on-primary group-data-[size=default]/switch:data-unchecked:size-3 group-data-[size=default]/switch:data-checked:size-4 group-data-[size=default]/switch:data-unchecked:translate-x-1 group-data-[size=default]/switch:data-checked:translate-x-[22px] group-data-[size=sm]/switch:data-unchecked:size-2.5 group-data-[size=sm]/switch:data-checked:size-3 group-data-[size=sm]/switch:data-unchecked:translate-x-1 group-data-[size=sm]/switch:data-checked:translate-x-[18px]"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
