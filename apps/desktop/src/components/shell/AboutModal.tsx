import { Anchor, Code, Divider, Group, List, Modal, Stack, Text, Title } from "@mantine/core";

const REPO = "https://github.com/Vibe-Coding-Base/PPXray";

export function AboutModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  return (
    <Modal opened={opened} onClose={onClose} title="About ppxray" size="md">
      <Stack gap="md">
        <Stack gap={2}>
          <Title order={4}>ppxray</Title>
          <Text size="xs" c="dimmed" className="mono">
            v{__APP_VERSION__}
          </Text>
        </Stack>

        <Text size="sm">
          Turns Proxifier into a per-process network monitor. It reads your{" "}
          <Code>.ppx</Code> rule list as an egress policy and the Proxifier log
          as per-process telemetry, then looks for what should not be there.
        </Text>

        <Stack gap={4}>
          <Title order={6}>Modules</Title>
          <List size="sm" spacing={2}>
            <List.Item>
              <b>Rules</b> — edit profiles with a lossless round trip, and see
              which rules shadow which
            </List.Item>
            <List.Item>
              <b>Exposure</b> — what the enabled rules actually let out
            </List.Item>
            <List.Item>
              <b>Log</b> — stream-parse logs into DuckDB, filter and visualise
            </List.Item>
            <List.Item>
              <b>Hunt</b> — run the detection catalog, triage what it finds
            </List.Item>
            <List.Item>
              <b>Assistant</b> — optional, off by default; asks a model to help
              read the log without handing it the log
            </List.Item>
          </List>
        </Stack>

        <Stack gap={4}>
          <Title order={6}>Privacy</Title>
          <Text size="sm">
            All analysis is local — profiles and logs never leave your machine,
            and there is no telemetry. Two things can make a request, both only
            when you ask: the update check under <b>Settings</b>, and the{" "}
            <b>Assistant</b>, which is off until you enable it. At its default
            level the assistant is sent the database schema and your question,
            never the contents of your log, and it can be pointed at a model
            running on this machine.
          </Text>
        </Stack>

        <Divider />

        <Stack gap={4}>
          <Group gap={6}>
            <Text size="sm" fw={500}>
              Tony Nguyen
            </Text>
            <Text size="sm" c="dimmed">
              - MIT licensed
            </Text>
          </Group>
          <Group gap="md">
            <Anchor size="xs" href={REPO} target="_blank" rel="noreferrer">
              Source
            </Anchor>
            <Anchor size="xs" href={`${REPO}/issues`} target="_blank" rel="noreferrer">
              Report an issue
            </Anchor>
            <Anchor
              size="xs"
              href={`${REPO}/releases/tag/v${__APP_VERSION__}`}
              target="_blank"
              rel="noreferrer"
            >
              Release notes
            </Anchor>
          </Group>
          <Text size="xs" c="dimmed">
            Bundles DuckDB, Mantine and uPlot, all MIT. Proxifier is a product
            of Initex and is not affiliated with this project.
          </Text>
        </Stack>
      </Stack>
    </Modal>
  );
}
