// Chip-list editor for targets / applications / ports.
//
// We deliberately don't use Mantine's `<TagsInput>` because we want:
// 1. per-chip validation state (red border for invalid entries);
// 2. preservation of original whitespace / casing;
// 3. semicolon OR newline OR comma as separators on paste, matching how
//    users copy lines out of the real `.ppx` file;
// 4. **edit-in-place**: double-click a chip to edit its value without
//    deleting + retyping.

import { ActionIcon, Box, Group, Text, TextInput, Tooltip,
  rem,
} from "@mantine/core";
import { IconAlertTriangle, IconX } from "@tabler/icons-react";
import { memo, useCallback, useEffect, useRef, useState, type ReactNode } from "react";

export type ChipValidator = (value: string) => boolean;
export type ChipBadge = { kind: string; color: string };
export type ChipKindResolver = (value: string) => ChipBadge | null;

interface ChipListProps {
  label: string;
  items: string[];
  placeholder?: string;
  mono?: boolean;
  validate?: ChipValidator;
  resolveKind?: ChipKindResolver;
  onChange: (next: string[]) => void;
  hint?: ReactNode;
}

export const ChipList = memo(function ChipList({
  label,
  items,
  placeholder,
  mono,
  validate,
  resolveKind,
  onChange,
  hint,
}: ChipListProps) {
  const [draft, setDraft] = useState("");

  const commit = useCallback(
    (input: string) => {
      const parts = splitEntry(input);
      if (parts.length === 0) return;
      const seen = new Set(items);
      const next = [...items];
      for (const p of parts) {
        if (!seen.has(p)) {
          next.push(p);
          seen.add(p);
        }
      }
      onChange(next);
      setDraft("");
    },
    [items, onChange],
  );

  const remove = useCallback(
    (idx: number) => {
      onChange(items.filter((_, i) => i !== idx));
    },
    [items, onChange],
  );

  /**
   * Replace `items[idx]` with whatever the user typed after double-clicking
   * into the chip. The new text is re-split using the paste separators, so
   * editing `"foo.com; bar.com"` into one chip produces two chips exactly
   * as if they were freshly typed.
   *
   * If the replacement is empty after trimming, the chip is removed.
   * Duplicates within the existing list are silently dropped.
   */
  const replace = useCallback(
    (idx: number, input: string) => {
      const parts = splitEntry(input);
      if (parts.length === 0) {
        remove(idx);
        return;
      }
      const next: string[] = [];
      const seen = new Set<string>();
      for (let i = 0; i < items.length; i++) {
        if (i === idx) {
          for (const p of parts) {
            if (!seen.has(p)) {
              next.push(p);
              seen.add(p);
            }
          }
          continue;
        }
        const cur = items[i]!;
        if (!seen.has(cur)) {
          next.push(cur);
          seen.add(cur);
        }
      }
      onChange(next);
    },
    [items, onChange, remove],
  );

  return (
    <Box>
      <Group gap={4} align="baseline" mb={4}>
        <Text size="xs" fw={600} tt="uppercase" c="dimmed">
          {label}
        </Text>
        <Text size="xs" c="dimmed">
          - {items.length}
        </Text>
        {hint && (
          <Text size="xs" c="dimmed" ml="auto">
            {hint}
          </Text>
        )}
      </Group>
      <Box
        style={{
          border: "1px solid var(--ppxray-border-strong)",
          borderRadius: 4,
          padding: 4,
          display: "flex",
          flexWrap: "wrap",
          gap: 4,
          minHeight: rem(40),
          alignItems: "flex-start",
        }}
      >
        {items.map((item, i) => (
          <Chip
            key={`${item}-${i}`}
            value={item}
            mono={mono}
            valid={validate ? validate(item) : true}
            badge={resolveKind?.(item) ?? null}
            onRemove={() => remove(i)}
            onReplace={(next) => replace(i, next)}
          />
        ))}
        <TextInput
          value={draft}
          onChange={(e) => setDraft(e.currentTarget.value)}
          placeholder={placeholder}
          variant="unstyled"
          size="xs"
          style={{ flex: 1, minWidth: rem(120) }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ";" || e.key === ",") {
              e.preventDefault();
              commit(draft);
            } else if (e.key === "Backspace" && draft === "" && items.length > 0) {
              remove(items.length - 1);
            }
          }}
          onBlur={() => {
            if (draft.trim()) commit(draft);
          }}
          onPaste={(e) => {
            const text = e.clipboardData.getData("text");
            if (/[;,\n]/.test(text)) {
              e.preventDefault();
              commit(text);
            }
          }}
        />
      </Box>
    </Box>
  );
});

interface ChipProps {
  value: string;
  mono?: boolean;
  valid: boolean;
  badge: ChipBadge | null;
  onRemove: () => void;
  onReplace: (next: string) => void;
}

function Chip({ value, mono, valid, badge, onRemove, onReplace }: ChipProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Reset draft whenever the incoming chip value changes (e.g. the store
  // was mutated elsewhere) so stale text doesn't linger.
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  // Autofocus + select-all when entering edit mode so Enter immediately
  // replaces the chip, or a single keystroke begins overwriting.
  useEffect(() => {
    if (editing) {
      queueMicrotask(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    }
  }, [editing]);

  function commit() {
    const trimmed = draft.trim();
    setEditing(false);
    if (trimmed === value.trim()) return; // no-op
    onReplace(trimmed);
  }

  const borderColor = valid
    ? "var(--ppxray-border-strong)"
    : "var(--mantine-color-red-7)";

  if (editing) {
    return (
      <TextInput
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit();
          } else if (e.key === "Escape") {
            e.preventDefault();
            setDraft(value);
            setEditing(false);
          }
        }}
        onBlur={commit}
        size="xs"
        styles={{
          input: {
            fontFamily: mono ? "var(--mono)" : undefined,
            fontSize: "var(--ppxray-text-dense)",
            minHeight: rem(24),
            height: rem(24),
            padding: "0 6px",
            borderRadius: 3,
          },
        }}
        style={{ maxWidth: rem(420) }}
      />
    );
  }

  return (
    <Group
      gap={4}
      wrap="nowrap"
      onDoubleClick={() => setEditing(true)}
      style={{
        border: `1px solid ${borderColor}`,
        background: "var(--ppxray-surface-elevated)",
        borderRadius: 3,
        padding: "1px 3px 1px 6px",
        maxWidth: "100%",
        alignItems: "center",
        cursor: "text",
      }}
      title="Double-click to edit"
    >
      {!valid && (
        <Tooltip label="Invalid entry" withArrow>
          <IconAlertTriangle size="0.85rem" color="var(--mantine-color-red-4)" />
        </Tooltip>
      )}
      {badge && (
        <Text size="xs" c={badge.color} fw={600} tt="uppercase">
          {badge.kind}
        </Text>
      )}
      <Text
        size="xs"
        className={mono ? "mono" : undefined}
        style={{
          maxWidth: rem(380),
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {value}
      </Text>
      <ActionIcon
        variant="transparent"
        size="xs"
        onClick={(e) => {
          e.stopPropagation();
          onRemove();
        }}
        aria-label="Remove"
      >
        <IconX size="0.85rem" />
      </ActionIcon>
    </Group>
  );
}

function splitEntry(raw: string): string[] {
  return raw
    .split(/[;,\n\r]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
