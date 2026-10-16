"use client";

import { Check, Monitor, Moon, Sun } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { REGISTRY } from "@/core/settings/registry";
import { useSetting } from "@/hooks/use-sieve";

const ICON = { system: Monitor, light: Sun, dark: Moon } as const;
const LABEL = { system: "System", light: "Light", dark: "Dark" } as const;

/** Theme picker: options come from the registry entry appearance.theme. */
export function ThemeMenu() {
  const [theme, setTheme] = useSetting("appearance.theme");
  const Current = ICON[theme];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <IconButton label={`Theme: ${LABEL[theme]}`}>
          <Current strokeWidth={1.75} />
        </IconButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-40 rounded-md bg-surface-3 p-1 shadow-l3">
        {REGISTRY["appearance.theme"].options.map((opt) => {
          const Icon = ICON[opt];
          return (
            <DropdownMenuItem key={opt} onSelect={() => void setTheme(opt)} className="h-9 gap-3 rounded-sm px-3 text-body">
              <Icon className="size-4" strokeWidth={1.75} />
              <span className="flex-1">{LABEL[opt]}</span>
              {opt === theme && <Check className="size-4 text-primary" strokeWidth={1.75} />}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
