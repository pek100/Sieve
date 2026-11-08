"use client";

import { ListFilter } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { LIST_GROUPS, listGroup, listOn, suggestedLists } from "@/core/filter-lists";
import type { FilterList } from "@/data/protocol";
import { ENGINE_AWAY_TEXT, type FiltersModel } from "@/hooks/use-filters";
import { ListGroup, ListRow, type ListActions } from "./list-group";
import type { RulesTarget } from "./rules-dialog";

function cardState({ catalogue, failed }: FiltersModel): CardState {
  if (failed !== null) return { kind: "error", message: failed };
  if (catalogue === null) return { kind: "loading" };
  if (catalogue.lists.length === 0) return { kind: "empty", line: "No filter lists yet", body: "The engine has not named any list." };
  return { kind: "ready" };
}

export const SUGGESTED_TEXT = "Suggested for your language";

/**
 * The language group: the lists for the languages this computer uses first,
 * then the rest behind one button, so a person who reads one language sees one
 * row, not nine. A list already on is always shown.
 */
function LanguageRows({ lists, languages, row, selection }: { lists: readonly FilterList[]; languages: readonly string[]; row: (l: FilterList, note?: string) => ReactNode; selection: FiltersModel["selection"] }) {
  const [all, setAll] = useState(false);
  const suggested = suggestedLists(lists, languages);
  const shown = lists.filter((l) => !suggested.includes(l) && (all || listOn(l, selection)));
  const hidden = lists.length - suggested.length - shown.length;
  return (
    <div className="flex flex-col gap-3">
      {suggested.length + shown.length > 0 && (
        <ul className="flex flex-col gap-3">
          {suggested.map((l) => row(l, SUGGESTED_TEXT))}
          {shown.map((l) => row(l))}
        </ul>
      )}
      {hidden > 0 && (
        <div>
          <Button variant="ghost" size="sm" onClick={() => setAll(true)}>
            {suggested.length + shown.length > 0 ? `Show ${hidden} more languages` : `Show ${hidden} languages`}
          </Button>
        </div>
      )}
    </div>
  );
}

/** The catalogue by what each list is for. A row that could not be read is left out and said in a line. */
export function ListCatalogue({
  model,
  disabled,
  nowMs,
  languages,
  onRules,
}: {
  model: FiltersModel;
  disabled: boolean;
  nowMs: number;
  /** The languages this computer uses (BCP 47 tags), best first. */
  languages: readonly string[];
  onRules: (target: RulesTarget) => void;
}) {
  const lists = model.catalogue?.lists ?? [];
  const dropped = model.catalogue?.dropped ?? 0;
  const reason = model.engineAnswers ? null : ENGINE_AWAY_TEXT;
  const actionsOf = (l: FilterList): ListActions => ({
    onRules: () => onRules({ id: l.id, title: l.title }),
    // Only a list that is on is downloaded; asking for one that is off would say nothing.
    onRefresh: listOn(l, model.selection) ? () => void model.refreshList(l.id) : undefined,
  });
  const row = (l: FilterList, note?: string) => (
    <ListRow key={l.id} list={l} selection={model.selection} onList={model.setList} actions={actionsOf(l)} reason={reason} disabled={disabled} nowMs={nowMs} note={note} />
  );
  return (
    <Card title="Filter lists" icon={<ListFilter strokeWidth={1.75} />} state={cardState(model)}>
      <div className="flex flex-col gap-8" data-list-catalogue="">
        {LIST_GROUPS.map((g) => {
          const of = lists.filter((l) => listGroup(l) === g.id);
          return (
            <ListGroup
              key={g.id}
              id={g.id}
              label={g.label}
              text={g.text}
              lists={of}
              selection={model.selection}
              onList={model.setList}
              onGroup={model.setGroup}
              actionsOf={actionsOf}
              reason={reason}
              disabled={disabled}
              nowMs={nowMs}
            >
              {g.id === "language" ? <LanguageRows lists={of} languages={languages} row={row} selection={model.selection} /> : undefined}
            </ListGroup>
          );
        })}
        {dropped > 0 && (
          <p className="text-label text-on-surface-muted" data-lists-dropped="">
            {dropped === 1 ? "1 list" : `${dropped} lists`} could not be read and {dropped === 1 ? "is" : "are"} not shown.
          </p>
        )}
      </div>
    </Card>
  );
}
