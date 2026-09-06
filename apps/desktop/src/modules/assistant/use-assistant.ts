// Asking a question, wherever it was asked from.
//
// The module and the drawer are two views of the same conversations, so the
// logic that gates and sends a question lives here rather than in either of
// them. It owns nothing itself: the exchanges people see are in the assistant
// store, and the transcript the model sees stays in Rust.

import { notifications } from "@mantine/notifications";
import { useQuery } from "@tanstack/react-query";
import { useCallback, useState } from "react";

import { useAssistantStore } from "@/stores/assistant-store";
import { llmAsk, llmMarkReviewed, llmStatus, type Task } from "./ipc";

export function useAssistantStatus() {
  return useQuery({ queryKey: ["llm", "status"], queryFn: llmStatus });
}

export function useAssistant(conversationId: string) {
  const [question, setQuestion] = useState("");
  const [previewFor, setPreviewFor] = useState<{ task: Task; input: string } | null>(null);

  const addQuestion = useAssistantStore((s) => s.addQuestion);
  const resolveExchange = useAssistantStore((s) => s.resolveExchange);
  const setBusy = useAssistantStore((s) => s.setBusy);

  const status = useAssistantStatus();
  const reviewed = status.data?.settings.reviewed_payload ?? false;

  const run = useCallback(
    async (task: Task, input: string) => {
      const shown = task === "review" ? "Review this log" : input;
      const exchangeId = addQuestion(conversationId, shown);
      setBusy(conversationId, true);
      try {
        const reply = await llmAsk(task, input, conversationId);
        resolveExchange(conversationId, exchangeId, { reply });
      } catch (e) {
        resolveExchange(conversationId, exchangeId, { error: String(e) });
      } finally {
        setBusy(conversationId, false);
      }
    },
    [conversationId, addQuestion, resolveExchange, setBusy],
  );

  // The first send goes through the payload preview. Afterwards questions go
  // straight out: the boundary the user approved has not moved, and asking
  // again every time would train them to click through it.
  const submit = useCallback(
    (task: Task, input: string) => {
      if (task !== "review" && !input.trim()) return;
      if (!reviewed) {
        setPreviewFor({ task, input });
        return;
      }
      if (task === "chat") setQuestion("");
      void run(task, input);
    },
    [reviewed, run],
  );

  const approveAndSend = useCallback(async () => {
    if (!previewFor) return;
    try {
      await llmMarkReviewed();
      await status.refetch();
      const { task, input } = previewFor;
      setPreviewFor(null);
      if (task === "chat") setQuestion("");
      await run(task, input);
    } catch (e) {
      notifications.show({ title: "Could not send", message: String(e), color: "red" });
    }
  }, [previewFor, run, status]);

  return {
    status,
    question,
    setQuestion,
    submit,
    previewFor,
    setPreviewFor,
    approveAndSend,
  };
}
