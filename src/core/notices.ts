/**
 * Notice bus (primitive B7). One queue for in-app toasts (with undo), the
 * Home banner and, later, desktop notifications. The toaster in
 * src/components/sieve/shell/notice-toaster.tsx is its only renderer today.
 */

export type NoticeKind = "info" | "success" | "error";

export interface NoticeAction {
  label: string;
  run: () => void;
}

export interface Notice {
  id: number;
  kind: NoticeKind;
  text: string;
  /** Where it shows. Toasts auto-dismiss; banners stay until dismissed. */
  surface: "toast" | "banner";
  action?: NoticeAction;
}

export interface NoticeBus {
  list(): readonly Notice[];
  push(n: Omit<Notice, "id" | "surface"> & { surface?: Notice["surface"] }): number;
  dismiss(id: number): void;
  subscribe(listener: () => void): () => void;
}

export function createNoticeBus(): NoticeBus {
  let notices: readonly Notice[] = [];
  let nextId = 1;
  const listeners = new Set<() => void>();
  const emit = () => listeners.forEach((l) => l());
  return {
    list: () => notices,
    push(n) {
      const id = nextId++;
      notices = [...notices, { surface: "toast", ...n, id }];
      emit();
      return id;
    },
    dismiss(id) {
      const next = notices.filter((n) => n.id !== id);
      if (next.length !== notices.length) {
        notices = next;
        emit();
      }
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
