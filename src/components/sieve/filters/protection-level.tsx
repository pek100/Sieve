"use client";

import { Shield } from "lucide-react";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { PROFILE_ORDER, PROFILE_TEXT, RECOMMENDED_PROFILE } from "@/core/filter-lists";
import { CUSTOM } from "@/core/profiles";
import type { FiltersModel } from "@/hooks/use-filters";
import { ChoiceList } from "./choice-list";

/**
 * The one choice at the top of Filters: how much Sieve blocks. The profile is
 * derived from the lists below; changing any of them shows Custom by itself,
 * with the way back to the recommended lists in one click.
 */
export function ProtectionLevel({ model, disabled }: { model: FiltersModel; disabled: boolean }) {
  const choices = PROFILE_ORDER.map((p) => ({ value: p, label: PROFILE_TEXT[p].label, note: p === RECOMMENDED_PROFILE ? "Recommended" : undefined, text: PROFILE_TEXT[p].text }));
  const custom = model.profile === CUSTOM;
  // A failed catalogue is said once, by the lists below; here only what it costs.
  if (model.failed !== null) {
    return (
      <Card title="Protection level" icon={<Shield strokeWidth={1.75} />}>
        <p className="text-body text-on-surface-muted" data-protection-level="">
          The levels are made of the filter lists, which could not be read, so none can be picked now.
        </p>
      </Card>
    );
  }
  return (
    <Card title="Protection level" icon={<Shield strokeWidth={1.75} />} state={model.catalogue === null ? { kind: "loading" } : undefined}>
      <div className="flex flex-col gap-3" data-protection-level={model.profile ?? ""}>
        <ChoiceList label="Protection level" choices={choices} current={model.profile} onChoose={model.setProfile} disabled={disabled} />
        {custom && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-3" data-profile-custom="">
            <p className="min-w-0 text-label text-on-surface-muted">
              <span className="text-body-strong text-on-surface">{PROFILE_TEXT.custom.label}.</span> {PROFILE_TEXT.custom.text}
            </p>
            <Button variant="secondary" size="sm" disabled={disabled} onClick={() => model.setProfile(RECOMMENDED_PROFILE)}>
              Back to recommended
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}
