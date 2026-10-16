import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "cn"
import { Slot } from "radix-ui"
import { StateLayer } from "@/components/sieve/primitives/state-layer"

// Sieve: buttons are pills with a Material state layer and ripple.
// filled (default) > tonal (secondary) > outlined (outline) > text (ghost, link).
// Destructive is tonal pink, never solid.
const buttonVariants = cva(
  "group/button relative isolate inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full border border-transparent font-medium whitespace-nowrap select-none transition-[background-color,color,box-shadow] duration-(--motion-fast) ease-standard disabled:pointer-events-none disabled:opacity-(--disabled-content) aria-invalid:border-blocked [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default: "bg-primary text-on-primary",
        secondary: "bg-surface-2 text-on-surface",
        outline: "border-outline-strong bg-transparent text-on-surface",
        ghost: "bg-transparent text-on-surface",
        destructive: "bg-blocked/16 text-blocked",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 gap-2 px-4 text-label has-data-[icon=inline-start]:pl-1.5",
        xs: "h-6 gap-1 px-2 text-caption [&_svg:not([class*='size-'])]:size-3",
        sm: "h-8 gap-1 px-3 text-label [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-10 gap-2 px-5 text-body-strong",
        icon: "size-9",
        "icon-xs": "size-6 [&_svg:not([class*='size-'])]:size-3",
        "icon-sm": "size-8",
        "icon-lg": "size-10 [&_svg:not([class*='size-'])]:size-5",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  children,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    >
      {asChild ? (
        children
      ) : (
        <>
          {children}
          {variant !== "link" && <StateLayer />}
        </>
      )}
    </Comp>
  )
}

export { Button, buttonVariants }
