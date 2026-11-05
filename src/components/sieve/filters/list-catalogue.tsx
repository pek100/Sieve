"use client";

import { ListFilter } from "lucide-react";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { LIST_GROUPS, listGroup } from "@/core/filter-lists";
import type { FiltersModel } from "@/hooks/use-filters";
import { ListGroup } from "./list-group";

function cardState({ catalogue, failed }: FiltersModel): CardState {
  if (failed !== null) return { kind: "error", message: failed };
  if (catalogue === null) return { kind: "loading" };
  if (catalogue.lists.length === 0) return { kind: "empty", line: "No filter lists yet", body: "The engine has not named any list." };
  return { kind: "ready" };
}

/** The catalogue by group. A row that could not be read is left out and said in a line. */
export function ListCatalogue({ model, disabled }: { model: FiltersModel; disabled: boolean }) {
  const lists = model.catalogue?.lists ?? [];
  const dropped = model.catalogue?.dropped ?? 0;
  return (
    <Card title="Filter lists" icon={<ListFilter strokeWidth={1.75} />} state={cardState(model)}>
      <div className="flex flex-col gap-6" data-list-catalogue="">
        {LIST_GROUPS.map((g) => (
          <ListGroup
            key={g.id}
            id={g.id}
            label={g.label}
            lists={lists.filter((l) => listGroup(l) === g.id)}
            selection={model.selection}
            onList={model.setList}
            onGroup={model.setGroup}
            disabled={disabled}
          />
        ))}
        {dropped > 0 && (
          <p className="text-label text-on-surface-muted" data-lists-dropped="">
            {dropped === 1 ? "1 list" : `${dropped} lists`} could not be read and {dropped === 1 ? "is" : "are"} not shown.
          </p>
        )}
      </div>
    </Card>
  );
}
