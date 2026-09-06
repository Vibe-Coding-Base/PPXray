// Assistant conversations, for the session only.
//
// Shared by the Assistant module and the drawer, so it lives in neither. This
// holds only what the user sees; the model's transcript stays in Rust under
// the same id, so the renderer cannot rewrite what the model was told.
//
// Nothing is persisted: above the default privacy level a conversation holds
// log content the user chose to share once.

import { createContext, useContext, useMemo, type ReactNode } from "react";
import { create, useStore as useZustandStore, type StoreApi } from "zustand";
import { useShallow } from "zustand/react/shallow";

import type { AssistantReply } from "@/modules/assistant/ipc";

export interface Exchange {
  id: number;
  question: string;
  reply: AssistantReply | null;
  error: string | null;
}

export interface Conversation {
  id: string;
  /** Taken from the first question, so the list reads as what was asked. */
  title: string;
  exchanges: Exchange[];
  /** True while a request for this conversation is in flight. */
  busy: boolean;
}

export interface AssistantSlice {
  conversations: Conversation[];
  activeId: string;
  /** The drawer, which can be opened from any module. */
  drawerOpen: boolean;

  setDrawerOpen: (open: boolean) => void;
  toggleDrawer: () => void;
  select: (id: string) => void;
  /** Start a fresh conversation and make it active. Returns its id. */
  startNew: () => string;
  remove: (id: string) => void;
  rename: (id: string, title: string) => void;
  /** Append a pending exchange; returns its local id. */
  addQuestion: (conversationId: string, question: string) => number;
  resolveExchange: (
    conversationId: string,
    exchangeId: number,
    patch: { reply?: AssistantReply; error?: string },
  ) => void;
  setBusy: (conversationId: string, busy: boolean) => void;
}

const UNTITLED = "New conversation";

function newConversation(): Conversation {
  return {
    // `crypto.randomUUID` is available in the webview and avoids a counter
    // that would collide across a conversation being removed and re-added.
    id: crypto.randomUUID(),
    title: UNTITLED,
    exchanges: [],
    busy: false,
  };
}

/** Enough of the question to recognise it in a list, cut on a word boundary. */
function titleFrom(question: string): string {
  const clean = question.trim().replace(/\s+/g, " ");
  if (clean.length <= 48) return clean || UNTITLED;
  return `${clean.slice(0, 48).replace(/\s\S*$/, "")}…`;
}

function createAssistantStore(): StoreApi<AssistantSlice> {
  const first = newConversation();
  return create<AssistantSlice>((set) => ({
    conversations: [first],
    activeId: first.id,
    drawerOpen: false,

    setDrawerOpen: (drawerOpen) => set({ drawerOpen }),
    toggleDrawer: () => set((s) => ({ drawerOpen: !s.drawerOpen })),
    select: (activeId) => set({ activeId }),

    startNew: () => {
      const created = newConversation();
      set((s) => ({ conversations: [created, ...s.conversations], activeId: created.id }));
      return created.id;
    },

    remove: (id) =>
      set((s) => {
        const remaining = s.conversations.filter((c) => c.id !== id);
        // Never leave the panel with nothing to render.
        const list = remaining.length > 0 ? remaining : [newConversation()];
        return {
          conversations: list,
          activeId: s.activeId === id ? list[0]!.id : s.activeId,
        };
      }),

    rename: (id, title) =>
      set((s) => ({
        conversations: s.conversations.map((c) =>
          c.id === id ? { ...c, title: title.trim() || UNTITLED } : c,
        ),
      })),

    addQuestion: (conversationId, question) => {
      const exchangeId = Date.now();
      set((s) => ({
        conversations: s.conversations.map((c) =>
          c.id !== conversationId
            ? c
            : {
                ...c,
                // The first question names the conversation; later ones do
                // not, so a renamed thread keeps its name.
                title: c.exchanges.length === 0 ? titleFrom(question) : c.title,
                exchanges: [
                  ...c.exchanges,
                  { id: exchangeId, question, reply: null, error: null },
                ],
              },
        ),
      }));
      return exchangeId;
    },

    resolveExchange: (conversationId, exchangeId, patch) =>
      set((s) => ({
        conversations: s.conversations.map((c) =>
          c.id !== conversationId
            ? c
            : {
                ...c,
                exchanges: c.exchanges.map((e) =>
                  e.id !== exchangeId
                    ? e
                    : { ...e, reply: patch.reply ?? null, error: patch.error ?? null },
                ),
              },
        ),
      })),

    setBusy: (conversationId, busy) =>
      set((s) => ({
        conversations: s.conversations.map((c) =>
          c.id === conversationId ? { ...c, busy } : c,
        ),
      })),
  }));
}

const AssistantStoreContext = createContext<StoreApi<AssistantSlice> | null>(null);

export function AssistantStoreProvider({ children }: { children: ReactNode }) {
  const store = useMemo(() => createAssistantStore(), []);
  return (
    <AssistantStoreContext.Provider value={store}>{children}</AssistantStoreContext.Provider>
  );
}

function useAssistantStoreApi(): StoreApi<AssistantSlice> {
  const store = useContext(AssistantStoreContext);
  if (!store) throw new Error("useAssistantStore must be used inside AssistantStoreProvider");
  return store;
}

export function useAssistantStore<T>(selector: (s: AssistantSlice) => T): T {
  return useZustandStore(useAssistantStoreApi(), selector);
}

export function useAssistantStoreShallow<T>(selector: (s: AssistantSlice) => T): T {
  return useZustandStore(useAssistantStoreApi(), useShallow(selector));
}

/** The conversation currently shown, guaranteed to exist. */
export function useActiveConversation(): Conversation {
  return useAssistantStore(
    (s) => s.conversations.find((c) => c.id === s.activeId) ?? s.conversations[0]!,
  );
}
