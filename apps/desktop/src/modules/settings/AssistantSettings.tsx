// The switch that changes what ppxray promises.
//
// Every other setting in this app is a preference. This one moves a
// boundary, so the card is written to be read rather than skimmed: the
// privacy level is a radio list with the consequence spelled out next to
// each option, the local-model path is offered first, and the payload
// preview and egress log are one click away rather than buried.

import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  Group,
  NumberInput,
  PasswordInput,
  Radio,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
  Tooltip,
  rem,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconCheck,
  IconDeviceDesktop,
  IconEye,
  IconFileText,
  IconKey,
  IconPlugConnected,
  IconRobot,
  IconWorldUpload,
} from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import type { DataScope, LlmSettings, ProviderKind } from "@ppxray/ipc-schema";
import { PayloadPreviewModal } from "@/modules/assistant/PayloadPreviewModal";
import {
  llmClearApiKey,
  llmProviderDefaults,
  llmSetApiKey,
  llmSetSettings,
  llmStatus,
  llmTestConnection,
  type ConnectionCheck,
} from "@/modules/assistant/ipc";
import { AuditLogModal } from "./AuditLogModal";

const PROVIDER_LABEL: Record<ProviderKind, string> = {
  "open-ai-compatible": "OpenAI-compatible (Ollama, LM Studio, vLLM, OpenRouter…)",
  anthropic: "Anthropic",
};

const SCOPES: { value: DataScope; label: string; detail: string }[] = [
  {
    value: "schema-only",
    label: "Schema only — recommended",
    detail:
      "Sends the table and column names and your question. The assistant writes SQL, ppxray runs it here, and the results are shown to you alone. No value from your log is ever transmitted.",
  },
  {
    value: "aggregates",
    label: "Aggregates",
    detail:
      "Also sends query results, after reducing hostnames to their registrable domain, process paths to a bare filename, and private addresses to their block. Needed for the assistant to interpret findings itself, and for “Review this log”.",
  },
  {
    value: "raw",
    label: "Raw events",
    detail:
      "Sends query results unchanged, including exact hostnames and addresses. Your Proxifier log is a record of every host this machine contacted — choose this only for an endpoint you control.",
  },
];

export function AssistantSettings() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["llm", "status"], queryFn: llmStatus });
  const defaults = useQuery({ queryKey: ["llm", "defaults"], queryFn: llmProviderDefaults });

  const [draft, setDraft] = useState<LlmSettings | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [testing, setTesting] = useState(false);
  const [check, setCheck] = useState<ConnectionCheck | null>(null);
  const [auditOpen, setAuditOpen] = useState(false);

  // Seed the form from the saved settings, and re-seed whenever the backend
  // reports something different — it clears `reviewed_payload` by itself when
  // the endpoint or privacy level moves, and the card has to show that.
  //
  // Compared by value, not identity: a refetch produces a fresh object every
  // time, and re-seeding on identity would wipe half-typed input. Adjusted
  // during render rather than in an effect, which is the supported way to
  // reset state from a changed input and avoids a second render pass.
  const [seeded, setSeeded] = useState<string | null>(null);
  const serverState = status.data ? JSON.stringify(status.data.settings) : null;
  if (serverState !== null && serverState !== seeded) {
    setSeeded(serverState);
    setDraft(status.data!.settings);
  }

  if (!draft || !status.data) return null;
  const saved = status.data;

  const providerDefault = defaults.data?.find((d) => d.provider === draft.provider);
  const activePreset = providerDefault?.presets.find(
    (x) => x.base_url === (draft.base_url.trim() || providerDefault.base_url),
  );

  async function commit(next: LlmSettings) {
    setBusy(true);
    try {
      const updated = await llmSetSettings(next);
      setDraft(updated.settings);
      qc.setQueryData(["llm", "status"], updated);
      await qc.invalidateQueries({ queryKey: ["llm"] });
    } catch (e) {
      notifications.show({ title: "Could not save", message: String(e), color: "red" });
      await status.refetch();
    } finally {
      setBusy(false);
    }
  }

  // A real request, so it proves the endpoint, the credential, the model name
  // and the parser all work together - which is more than storing a key can.
  async function runTest() {
    setTesting(true);
    setCheck(null);
    try {
      setCheck(await llmTestConnection());
    } catch (e) {
      setCheck({ ok: false, summary: String(e), hint: null, latency_ms: null, model: null });
    } finally {
      setTesting(false);
    }
  }

  async function saveKey() {
    setBusy(true);
    try {
      await llmSetApiKey(apiKey);
      setApiKey("");
      await status.refetch();
      notifications.show({ message: "Key stored in the OS credential store", color: "teal" });
    } catch (e) {
      notifications.show({ title: "Could not store the key", message: String(e), color: "red" });
    } finally {
      setBusy(false);
    }
  }

  async function clearKey() {
    setBusy(true);
    try {
      await llmClearApiKey();
      await status.refetch();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card withBorder radius="sm" p="md">
      <Group gap="xs" mb="xs">
        <IconRobot size="1.1rem" />
        <Text fw={600}>Assistant</Text>
        <Badge variant="light" color={draft.enabled ? "teal" : "gray"}>
          {draft.enabled ? "on" : "off"}
        </Badge>
      </Group>

      <Group justify="space-between" wrap="nowrap" mb="sm">
        <Text size="sm" c="dimmed" style={{ flex: 1 }}>
          Lets a language model help you read this log — it writes queries,
          ppxray runs them locally, and it explains rules. Off by default. The
          update check is the only other request this app makes.
        </Text>
        <Switch
          checked={draft.enabled}
          disabled={busy}
          onChange={(e) => void commit({ ...draft, enabled: e.currentTarget.checked })}
        />
      </Group>

      {draft.enabled && (
        <Stack gap="md">
          <Stack gap={4}>
            <Text size="sm" fw={500}>
              Where the model runs
            </Text>
            <Select
              data={(defaults.data ?? []).map((d) => ({
                value: d.provider,
                label: PROVIDER_LABEL[d.provider],
              }))}
              value={draft.provider}
              allowDeselect={false}
              disabled={busy}
              onChange={(v) => v && void commit({ ...draft, provider: v as ProviderKind })}
            />
            {providerDefault && providerDefault.presets.length > 1 && (
              <Select
                label="Known endpoints"
                description="Fills in the URL and a starting model — you can still edit both"
                placeholder="Pick one…"
                data={providerDefault.presets.map((x) => ({
                  value: x.base_url,
                  label: x.local ? `${x.label} — no egress` : x.label,
                }))}
                value={
                  providerDefault.presets.find((x) => x.base_url === draft.base_url)?.base_url ??
                  null
                }
                disabled={busy}
                onChange={(v) => {
                  const picked = providerDefault.presets.find((x) => x.base_url === v);
                  if (picked) {
                    void commit({ ...draft, base_url: picked.base_url, model: picked.model });
                  }
                }}
              />
            )}
            {activePreset && (
              <Text size="sm" c={activePreset.local ? "teal" : "dimmed"}>
                {activePreset.note}
              </Text>
            )}
            <Group grow gap="xs">
              <TextInput
                label="Endpoint"
                placeholder={providerDefault?.base_url}
                value={draft.base_url}
                disabled={busy}
                onChange={(e) => setDraft({ ...draft, base_url: e.currentTarget.value })}
                onBlur={() => void commit(draft)}
              />
              <TextInput
                label="Model"
                placeholder={providerDefault?.model}
                value={draft.model}
                disabled={busy}
                onChange={(e) => setDraft({ ...draft, model: e.currentTarget.value })}
                onBlur={() => void commit(draft)}
              />
            </Group>
            <Group gap={6}>
              {saved.local_endpoint ? (
                <>
                  <IconDeviceDesktop size="0.9rem" color="var(--mantine-color-teal-5)" />
                  <Text size="sm" c="teal">
                    <b>{saved.effective_base_url}</b> is on this machine — nothing
                    leaves it, whichever privacy level you choose.
                  </Text>
                </>
              ) : (
                <>
                  <IconWorldUpload size="0.9rem" color="var(--mantine-color-yellow-5)" />
                  <Text size="sm" c="dimmed">
                    Requests go to <b>{saved.effective_base_url}</b> as{" "}
                    <Code>{saved.effective_model}</Code>.
                  </Text>
                </>
              )}
            </Group>
          </Stack>

          <Stack gap={4}>
            <Group gap={6}>
              <IconKey size="1rem" />
              <Text size="sm" fw={500}>
                API key
              </Text>
              {saved.has_key && (
                <Badge variant="light" color="teal">
                  stored
                </Badge>
              )}
            </Group>
            <Text size="sm" c="dimmed">
              Kept in the OS credential store — Windows Credential Manager,
              macOS Keychain, or the Linux Secret Service — not in ppxray&apos;s
              settings file. It is read when a request is sent and is never
              returned to this window. A local Ollama or llama.cpp endpoint
              needs no key.
            </Text>
            <Group gap="xs" align="flex-end">
              <PasswordInput
                style={{ flex: 1 }}
                placeholder={saved.has_key ? "Replace the stored key…" : "Paste a key…"}
                value={apiKey}
                disabled={busy}
                onChange={(e) => setApiKey(e.currentTarget.value)}
              />
              <Button disabled={!apiKey.trim() || busy} onClick={() => void saveKey()}>
                Store
              </Button>
              {saved.has_key && (
                <Button variant="subtle" color="red" onClick={() => void clearKey()}>
                  Remove
                </Button>
              )}
            </Group>
          </Stack>

          <Stack gap={6}>
            <Text size="sm" fw={500}>
              What may leave this machine
            </Text>
            <Radio.Group
              value={draft.data_scope}
              onChange={(v) => void commit({ ...draft, data_scope: v as DataScope })}
            >
              <Stack gap={8} mt={4}>
                {SCOPES.map((s) => (
                  <Radio
                    key={s.value}
                    value={s.value}
                    disabled={busy}
                    label={
                      <Stack gap={0}>
                        <Text size="sm" fw={500}>{s.label}</Text>
                        <Text size="sm" c="dimmed">
                          {s.detail}
                        </Text>
                      </Stack>
                    }
                  />
                ))}
              </Stack>
            </Radio.Group>
            {draft.data_scope === "raw" && (
              <Alert variant="light" color="red" p="xs">
                <Text size="sm">
                  At this level a request can contain the hosts you visited and
                  when. Use it only against an endpoint you run yourself.
                </Text>
              </Alert>
            )}
          </Stack>

          <Group justify="space-between" align="flex-end">
            <Tooltip
              withArrow
              multiline
              w={rem(280)}
              label="How many rows a single query may return. Also the cap on how much of a result can be shared, at the levels that share results."
            >
              <NumberInput
                label="Row limit per query"
                min={1}
                max={5000}
                w={rem(160)}
                value={draft.max_result_rows}
                disabled={busy}
                onChange={(v) =>
                  setDraft({ ...draft, max_result_rows: Math.max(1, Number(v) || 1) })
                }
                onBlur={() => void commit(draft)}
              />
            </Tooltip>
            <Group gap="xs">
              <Button
                variant="default"
                leftSection={<IconPlugConnected size="1rem" />}
                loading={testing}
                onClick={() => void runTest()}
              >
                Test connection
              </Button>
              <Button
                variant="default"
                leftSection={<IconEye size="1rem" />}
                onClick={() => setPreviewOpen(true)}
              >
                Preview a request
              </Button>
              <Button
                variant="default"
                leftSection={<IconFileText size="1rem" />}
                onClick={() => setAuditOpen(true)}
              >
                Egress log
              </Button>
            </Group>
          </Group>

          {check && (
            <Alert
              variant="light"
              color={check.ok ? "teal" : "red"}
              p="xs"
              icon={check.ok ? <IconCheck size="1rem" /> : <IconAlertTriangle size="1rem" />}
              withCloseButton
              onClose={() => setCheck(null)}
            >
              <Text size="sm">{check.summary}</Text>
              {check.hint && (
                <Text size="xs" c="dimmed" mt={2}>
                  {check.hint}
                </Text>
              )}
            </Alert>
          )}

          {!draft.reviewed_payload && (
            <Alert variant="light" color="blue" p="xs">
              <Text size="sm">
                Nothing is sent until you have looked at one request in full.
                The first question you ask will show it to you.
              </Text>
            </Alert>
          )}

          <Text size="sm" c="dimmed">
            Every request is appended to{" "}
            <Anchor
              size="sm"
              component="button"
              type="button"
              onClick={() => setAuditOpen(true)}
            >
              {saved.audit_path}
            </Anchor>{" "}
            — endpoint, model, privacy level, byte count and a SHA-256 of the
            body, including the requests ppxray refused to send.
          </Text>
        </Stack>
      )}

      <PayloadPreviewModal
        opened={previewOpen}
        onClose={() => setPreviewOpen(false)}
        task="chat"
        input="Which processes reached the most distinct hosts?"
      />
      <AuditLogModal opened={auditOpen} onClose={() => setAuditOpen(false)} />
    </Card>
  );
}
