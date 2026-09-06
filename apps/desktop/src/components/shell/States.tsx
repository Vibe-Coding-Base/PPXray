// Shared loading / error / empty blocks, and the helper that makes a
// non-`<button>` element behave like one.
//
// Failure and emptiness must not look alike: in a security tool, "no threats
// found" and "the detector is not running" are different answers. Routing
// every panel through these keeps that distinction, and the wording,
// consistent.

import { Box, Button, Group, Loader, Stack, Text,
  rem,
  Title,} from "@mantine/core";
import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";
import type { KeyboardEvent, ReactNode } from "react";

const EMPTY = Object.freeze([]) as readonly never[];

/**
 * Unwrap a query result to an array, with a stable identity when empty.
 *
 * `query.data ?? []` mints a fresh array on every render, so every
 * `useMemo` / `useCallback` downstream of it re-runs every time and the memo
 * silently does nothing. One frozen instance keeps the identity stable.
 */
export function rows<T>(data: T[] | undefined): T[] {
  return data ?? (EMPTY as unknown as T[]);
}

// ---------------------------------------------------------------------------
// State blocks
// ---------------------------------------------------------------------------

/** Shared frame so all three states occupy the same space and alignment. */
function Block({ children, compact }: { children: ReactNode; compact?: boolean }) {
  return (
    <Stack align="center" justify="center" gap={6} p={compact ? "sm" : "lg"} ta="center">
      {children}
    </Stack>
  );
}

export function LoadingBlock({
  label = "Loading…",
  compact,
}: {
  label?: string;
  compact?: boolean;
}) {
  return (
    <Block compact={compact}>
      <Group gap={8} wrap="nowrap">
        <Loader size="xs" />
        <Text size="xs" c="dimmed">
          {label}
        </Text>
      </Group>
    </Block>
  );
}

/**
 * A failed read. Always shows the underlying message: these are local IPC
 * errors, and the text ("no log loaded", a DuckDB binder error) is usually
 * the actionable part.
 */
export function ErrorBlock({
  error,
  onRetry,
  compact,
}: {
  error: unknown;
  onRetry?: () => void;
  compact?: boolean;
}) {
  return (
    <Block compact={compact}>
      <IconAlertTriangle size={compact ? 16 : 22} stroke={1.5} color="var(--mantine-color-red-6)" />
      <Text size="xs" fw={600} c="red.5">
        Couldn&apos;t load this
      </Text>
      <Text size="xs" c="dimmed" maw={rem(360)} style={{ wordBreak: "break-word" }}>
        {messageOf(error)}
      </Text>
      {onRetry && (
        <Button
          size="compact-sm"
          variant="default"
          leftSection={<IconRefresh size="0.85rem" />}
          onClick={onRetry}
          mt={4}
        >
          Retry
        </Button>
      )}
    </Block>
  );
}

/**
 * Nothing to show. `hint` should say what would change that — a filter to
 * relax, a button to press — rather than restating that the list is empty.
 */
export function EmptyBlock({
  icon,
  title,
  hint,
  action,
  compact,
}: {
  icon?: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <Block compact={compact}>
      {icon}
      <Text size="xs" c="dimmed">
        {title}
      </Text>
      {hint && (
        <Text size="xs" c="dimmed" opacity={0.75} maw={rem(360)}>
          {hint}
        </Text>
      )}
      {action && <Box mt={4}>{action}</Box>}
    </Block>
  );
}

/**
 * The "this module has nothing loaded yet" screen.
 *
 * Distinct from [`EmptyBlock`], which is the small inline notice a table or
 * panel shows when a filter matches no rows. This one is the whole viewport
 * on first run, so it gets a real heading, a sentence of context and the
 * button that fixes it.
 */
export function ModuleEmptyState({
  icon,
  title,
  description,
  actions,
  secondaryActions,
  footnote,
}: {
  icon: ReactNode;
  title: string;
  description: ReactNode;
  /** Primary action first. Omit only when the module genuinely cannot act. */
  actions?: ReactNode;
  /** Sits beside the primary one, e.g. "load the bundled sample". */
  secondaryActions?: ReactNode;
  /** One line of secondary guidance, e.g. where else to go. */
  footnote?: ReactNode;
}) {
  return (
    <Stack align="center" gap="sm" p="xl" mt="xl">
      {icon}
      <Title order={4}>{title}</Title>
      <Text c="dimmed" size="sm" maw={rem(460)} ta="center">
        {description}
      </Text>
      {(actions || secondaryActions) && (
        <Group gap="xs" mt={4}>
          {actions}
          {secondaryActions}
        </Group>
      )}
      {footnote && (
        <Text c="dimmed" size="xs" maw={rem(460)} ta="center" mt={4}>
          {footnote}
        </Text>
      )}
    </Stack>
  );
}

function messageOf(error: unknown): string {
  if (error == null) return "Unknown error.";
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

// ---------------------------------------------------------------------------
// Keyboard-reachable click targets
// ---------------------------------------------------------------------------

/**
 * Props that make a `<div>` / `<Text>` behave like a button for keyboard and
 * screen-reader users.
 *
 * The log and hunt views drive their whole interaction loop through clickable
 * rows and cells — click a process to filter, click an alert to open it. Those
 * were plain `onClick` handlers on non-interactive elements, so none of it was
 * reachable by keyboard, in an app that otherwise advertises a command palette
 * and a shortcut sheet.
 *
 * Spread the result; do not also pass your own `onClick`.
 */
export function clickable(
  onClick: (() => void) | undefined,
  label?: string,
): {
  role?: "button";
  tabIndex?: 0;
  "aria-label"?: string;
  onClick?: () => void;
  onKeyDown?: (e: KeyboardEvent) => void;
} {
  if (!onClick) return {};
  return {
    role: "button",
    tabIndex: 0,
    "aria-label": label,
    onClick,
    onKeyDown: (e: KeyboardEvent) => {
      // Space scrolls the page by default; Enter does nothing on a div.
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        onClick();
      }
    },
  };
}
