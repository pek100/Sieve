"use client";

import { useState } from "react";
import { DomainField } from "@/components/sieve/filters/domain-field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { ExclusionsModel } from "./use-exclusions";

/** The select's value for no app in particular: no exe file name has a space. */
const ALL_APPS = "all apps";

/** Add a site, for every app or for one that is running now (plan 8.2). */
export function ExclusionsAdd({ model }: { model: Pick<ExclusionsModel, "add" | "running"> }) {
  const [app, setApp] = useState(ALL_APPS);
  return (
    <DomainField label="Add a site not to decrypt" disabled={false} onAdd={(host) => model.add(host, app === ALL_APPS ? null : app)}>
      <Select value={app} onValueChange={setApp}>
        <SelectTrigger aria-label="For which app" className="h-9 max-w-full min-w-0 rounded-full bg-inset px-3 text-label">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL_APPS}>All apps</SelectItem>
          {model.running.map((r) => (
            <SelectItem key={r.file} value={r.file}>
              {r.name === r.file ? r.file : `${r.name} (${r.file})`}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </DomainField>
  );
}
