"use client"

import { Toaster as Sonner, type ToasterProps } from "sonner"
import { CircleCheckIcon, InfoIcon, TriangleAlertIcon, OctagonXIcon, Loader2Icon } from "lucide-react"
import { useResolvedTheme } from "@/hooks/use-theme"

// Sieve: theme comes from the appearance.theme setting; toasts are level 4.
const Toaster = ({ ...props }: ToasterProps) => {
  const theme = useResolvedTheme()

  return (
    <Sonner
      theme={theme}
      className="toaster group"
      icons={{
        success: <CircleCheckIcon className="size-4 text-primary" strokeWidth={1.75} />,
        info: <InfoIcon className="size-4 text-info" strokeWidth={1.75} />,
        warning: <TriangleAlertIcon className="size-4 text-warning" strokeWidth={1.75} />,
        error: <OctagonXIcon className="size-4 text-blocked" strokeWidth={1.75} />,
        loading: <Loader2Icon className="size-4 animate-spin" strokeWidth={1.75} />,
      }}
      style={
        {
          "--normal-bg": "var(--surface-3)",
          "--normal-text": "var(--on-surface)",
          "--normal-border": "var(--rim-3)",
          "--border-radius": "var(--radius-md)",
        } as React.CSSProperties
      }
      toastOptions={{
        classNames: {
          toast: "cn-toast shadow-l4 font-sans text-body",
          actionButton: "rounded-full! bg-primary! text-on-primary! font-medium!",
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
