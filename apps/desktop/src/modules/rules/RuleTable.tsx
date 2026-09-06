// Virtualized rule table with drag-drop reorder and multi-select.
//
// Design notes:
// - Rows are virtualized via `@tanstack/react-virtual`. We target comfortable
//   use with ~5k rules at 60fps scroll; the sample profile has ~120.
// - Drag-drop uses `@dnd-kit/sortable`. Keyboard access (Space to pick up,
//   arrows to move, Space to drop) is provided by the sortable keyboard
//   coordinates helper.
// - Multi-select mimics OS conventions: click = replace, Ctrl/Cmd+click =
//   toggle, Shift+click = range from anchor.
// - The table stores row heights in a `useRef` map so rows with differing
//   content (e.g. 10 chips vs 1) still virtualize correctly.

import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import { restrictToVerticalAxis } from "@dnd-kit/modifiers";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { Badge, Box, Checkbox, Group, Switch, Text, Tooltip,
  rem,
} from "@mantine/core";
import { IconAlertTriangle, IconGripVertical } from "@tabler/icons-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { createContext, useCallback, useContext, useMemo, useRef } from "react";

import type { Rule, RuleAction } from "@ppxray/ipc-schema";
import {
  ColumnResizeHandle,
  useColumnWidths,
  type ColumnSpec,
} from "@/components/shell/ResizableColumns";
import { useRem } from "@/hooks/use-row-height";
import { useProfileStoreShallow } from "@/stores/profile-store";
import type { EnrichedShadow } from "./RuleModule";

/** 40px at the original 16px base, kept proportional as the user
 *  changes the interface size (see `hooks/use-row-height.ts`). */
const ROW_HEIGHT_REM = 2.5;

// Column spec for the rule table. The order here drives both the header and
// the row body grid; widths persist via `useColumnWidths`.
const COLUMN_SPEC: ColumnSpec[] = [
  { id: "drag", label: "", defaultWidth: 22, minWidth: 22, maxWidth: 22, fixed: true },
  { id: "select", label: "", defaultWidth: 28, minWidth: 28, maxWidth: 28, fixed: true },
  { id: "index", label: "#", defaultWidth: 44, minWidth: 30, maxWidth: 80 },
  { id: "enabled", label: "On", defaultWidth: 56, minWidth: 50, maxWidth: 90 },
  { id: "name", label: "Name", defaultWidth: 220, minWidth: 80 },
  { id: "action", label: "Action", defaultWidth: 110, minWidth: 70 },
  { id: "ports", label: "Ports", defaultWidth: 110, minWidth: 60 },
  { id: "targets", label: "Targets", defaultWidth: 320, minWidth: 100 },
  { id: "applications", label: "Applications", defaultWidth: 320, minWidth: 100, fixed: true },
];

// Provide the live grid template + the total minimum width to descendants.
// We use the flex template so the last column fills available slack — that
// removes the right-side whitespace and the "last column is truncated while
// the rest of the viewport is empty" artifact we had with fixed widths.
const GridTemplateContext = createContext<{ template: string; minWidth: number }>({
  template: COLUMN_SPEC.map((c, i) =>
    i === COLUMN_SPEC.length - 1 ? `minmax(${c.defaultWidth}px, 1fr)` : `${c.defaultWidth}px`,
  ).join(" "),
  minWidth: COLUMN_SPEC.reduce((s, c) => s + c.defaultWidth, 0),
});

interface RuleTableProps {
  /** Filtered rows, each with its ORIGINAL index in the profile. */
  rows: { rule: Rule; index: number }[];
  overshadows: Map<number, EnrichedShadow>;
}

export function RuleTable({ rows, overshadows }: RuleTableProps) {
  const parentRef = useRef<HTMLDivElement | null>(null);
  const colWidths = useColumnWidths("rules-table", COLUMN_SPEC);
  const gridContext = useMemo(
    () => ({ template: colWidths.flexTemplate, minWidth: colWidths.minRowWidth }),
    [colWidths.flexTemplate, colWidths.minRowWidth],
  );

  const { selectedIndices, detailIndex, toggleSelection, openDetail, toggleRule, moveRules } =
    useProfileStoreShallow((s) => ({
      selectedIndices: s.selectedIndices,
      detailIndex: s.detailIndex,
      toggleSelection: s.toggleSelection,
      openDetail: s.openDetail,
      toggleRule: s.toggleRule,
      moveRules: s.moveRules,
    }));

  const ids = useMemo(() => rows.map(({ index }) => `rule-${index}`), [rows]);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const rowHeight = useRem(ROW_HEIGHT_REM);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 8,
  });

  const onDragEnd = useCallback(
    (event: DragEndEvent) => {
      const { active, over } = event;
      if (!over || active.id === over.id) return;

      const fromVis = ids.indexOf(String(active.id));
      const toVis = ids.indexOf(String(over.id));
      if (fromVis < 0 || toVis < 0) return;

      // Translate from visible-row indices to profile indices.
      const fromOrig = rows[fromVis]!.index;
      const toOrigRaw = rows[toVis]!.index;

      // Build the target in original-index coords: insert "before" the target
      // row from above, or "after" if dragging down. To keep semantics simple,
      // we treat `to` as a 0-based insertion point in the moved-out list.
      const target = fromOrig < toOrigRaw ? toOrigRaw + 1 : toOrigRaw;
      moveRules([fromOrig], target);
    },
    [ids, rows, moveRules],
  );

  return (
    <GridTemplateContext.Provider value={gridContext}>
      <Box
        ref={parentRef}
        style={{
          flex: 1,
          overflow: "auto",
          border: "1px solid var(--ppxray-border)",
          borderRadius: 4,
          background: "var(--ppxray-surface)",
        }}
      >
        <HeaderRow
          widths={colWidths.widths}
          setWidth={colWidths.setWidth}
          minWidth={colWidths.minRowWidth}
          template={colWidths.flexTemplate}
        />
        <DndContext
          sensors={sensors}
          collisionDetection={closestCenter}
          onDragEnd={onDragEnd}
          modifiers={[restrictToVerticalAxis]}
        >
          <SortableContext items={ids} strategy={verticalListSortingStrategy}>
            <div
              style={{
                height: `${virtualizer.getTotalSize()}px`,
                minWidth: `${colWidths.minRowWidth}px`,
                width: "100%",
                position: "relative",
              }}
            >
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const item = rows[virtualRow.index];
              if (!item) return null;
              const { rule, index } = item;
              const shadow = overshadows.get(index);
              return (
                <RowContainer
                  key={ids[virtualRow.index]}
                  id={ids[virtualRow.index]!}
                  transformTop={virtualRow.start}
                >
                  <RuleRow
                    rule={rule}
                    index={index}
                    selected={selectedIndices.has(index)}
                    active={detailIndex === index}
                    shadow={shadow ?? null}
                    onToggleSelect={(mode) => toggleSelection(index, mode)}
                    onToggleEnabled={() => toggleRule(index)}
                    onOpenDetail={() => openDetail(index)}
                  />
                </RowContainer>
              );
            })}
            {rows.length === 0 && (
              <Box p="lg" ta="center">
                <Text size="sm" c="dimmed">
                  No rules match your filter.
                </Text>
              </Box>
            )}
            </div>
          </SortableContext>
        </DndContext>
      </Box>
    </GridTemplateContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Row container (sortable + absolute positioning for virtualization)
// ---------------------------------------------------------------------------

function RowContainer({
  id,
  transformTop,
  children,
}: {
  id: string;
  transformTop: number;
  children: React.ReactNode;
}) {
  const { setNodeRef, transform, transition, isDragging } = useSortable({ id });
  return (
    <div
      ref={setNodeRef}
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        transform: CSS.Transform.toString(
          transform ? { ...transform, x: 0 } : { x: 0, y: transformTop, scaleX: 1, scaleY: 1 },
        ),
        transition: transition ?? undefined,
        zIndex: isDragging ? 10 : 0,
        opacity: isDragging ? 0.85 : 1,
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

interface HeaderRowProps {
  widths: number[];
  setWidth: (i: number, w: number) => void;
  minWidth: number;
  template: string;
}

function HeaderRow({ widths, setWidth, minWidth, template }: HeaderRowProps) {
  return (
    <div
      style={{
        position: "sticky",
        top: 0,
        zIndex: 5,
        background: "var(--ppxray-surface-elevated)",
        borderBottom: "1px solid var(--ppxray-border-strong)",
        display: "grid",
        gridTemplateColumns: template,
        alignItems: "center",
        padding: "0 0 0 8px",
        height: rem(32),
        minWidth: `${minWidth}px`,
        width: "100%",
        fontSize: "var(--ppxray-text-dense)",
        textTransform: "uppercase",
        color: "var(--mantine-color-dimmed)",
        fontWeight: 600,
        letterSpacing: 0.3,
      }}
    >
      {COLUMN_SPEC.map((col, i) => (
        <div
          key={col.id}
          style={{
            position: "relative",
            height: "100%",
            display: "flex",
            alignItems: "center",
            paddingRight: col.fixed ? 0 : 6,
            overflow: "hidden",
            whiteSpace: "nowrap",
            textOverflow: "ellipsis",
          }}
        >
          {col.label}
          {!col.fixed && (
            <ColumnResizeHandle
              className="ppxray-col-resize"
              currentWidth={widths[i] ?? col.defaultWidth}
              onResize={(w) => setWidth(i, w)}
            />
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

interface RuleRowProps {
  rule: Rule;
  index: number;
  selected: boolean;
  active: boolean;
  shadow: EnrichedShadow | null;
  onToggleSelect: (mode: "single" | "toggle" | "range") => void;
  onToggleEnabled: () => void;
  onOpenDetail: () => void;
}

function RuleRow({
  rule,
  index,
  selected,
  active,
  shadow,
  onToggleSelect,
  onToggleEnabled,
  onOpenDetail,
}: RuleRowProps) {
  const rowHeight = useRem(ROW_HEIGHT_REM);
  const dragHandle = useSortable({ id: `rule-${index}` });
  const { template, minWidth } = useContext(GridTemplateContext);

  return (
    <div
      onClick={(e) => {
        // Ignore clicks from the drag handle / toggle / checkbox.
        const target = e.target as HTMLElement;
        if (target.closest('[data-interactive="true"]')) return;
        const mode = e.shiftKey ? "range" : e.ctrlKey || e.metaKey ? "toggle" : "single";
        onToggleSelect(mode);
        onOpenDetail();
      }}
      style={{
        display: "grid",
        gridTemplateColumns: template,
        minWidth: `${minWidth}px`,
        width: "100%",
        alignItems: "center",
        // Extra left padding creates room for the yellow shadow-accent stripe
        // rendered via `box-shadow`. Keeps the grid geometry unchanged for
        // non-shadowed rows.
        padding: "0 8px 0 12px",
        height: rowHeight,
        background: active
          ? "var(--mantine-color-blue-light)"
          : selected
            ? "var(--ppxray-surface-elevated)"
            : shadow
              ? "color-mix(in srgb, var(--mantine-color-yellow-7) 8%, transparent)"
              : "transparent",
        borderBottom: "1px solid var(--ppxray-row-divider)",
        // Shadow rows get a 3px yellow left stripe that's instantly scannable
        // even when the row is otherwise at rest, plus a subtle fill tint.
        boxShadow: shadow
          ? "inset 3px 0 0 0 var(--mantine-color-yellow-6)"
          : undefined,
        cursor: "pointer",
        userSelect: "none",
      }}
    >
      <span
        data-interactive="true"
        ref={dragHandle.setActivatorNodeRef}
        {...dragHandle.attributes}
        {...dragHandle.listeners}
        style={{
          cursor: "grab",
          display: "flex",
          alignItems: "center",
          color: "var(--mantine-color-dimmed)",
        }}
        aria-label="Drag to reorder"
      >
        <IconGripVertical size="1rem" />
      </span>

      <div data-interactive="true" onClick={(e) => e.stopPropagation()}>
        <Checkbox
          size="xs"
          checked={selected}
          onChange={(e) =>
            onToggleSelect(
              e.nativeEvent instanceof MouseEvent && e.nativeEvent.shiftKey
                ? "range"
                : "toggle",
            )
          }
          aria-label="Select rule"
        />
      </div>

      <Text size="xs" c="dimmed" className="mono">
        {index + 1}
      </Text>

      <div data-interactive="true" onClick={(e) => e.stopPropagation()}>
        <Switch
          size="xs"
          checked={rule.enabled}
          onChange={onToggleEnabled}
          aria-label="Toggle enabled"
        />
      </div>

      <Group gap={6} wrap="nowrap" style={{ overflow: "hidden" }}>
        <Text
          size="sm"
          fw={rule.enabled ? 500 : 400}
          c={rule.enabled ? undefined : "dimmed"}
          style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          title={rule.name}
        >
          {rule.name}
        </Text>
        {shadow && <ShadowChip shadow={shadow} />}
      </Group>

      <ActionBadge action={rule.action} />

      <ListPreview items={rule.ports} mono emptyLabel="any" />
      <ListPreview items={rule.targets} emptyLabel="any" />
      <ListPreview items={rule.applications} mono emptyLabel="any" />
    </div>
  );
}

function ActionBadge({ action }: { action: RuleAction }) {
  switch (action.kind) {
    case "direct":
      return <Badge color="teal" variant="light">Direct</Badge>;
    case "block":
      return <Badge color="red" variant="light">Block</Badge>;
    case "proxy":
      return (
        <Badge color="blue" variant="light">
          Proxy #{action.proxy_id}
        </Badge>
      );
    case "chain":
      return (
        <Badge color="violet" variant="light">
          Chain #{action.chain_id}
        </Badge>
      );
  }
}

// ---------------------------------------------------------------------------
// Shadow badge
// ---------------------------------------------------------------------------

function ShadowChip({ shadow }: { shadow: EnrichedShadow }) {
  const { reason } = shadow;
  // Strongest signal first: `Identical` > `Covers` > `Any`. This label is
  // shown on the badge itself so shadowed rules are scannable at a glance.
  const label =
    reason.targets === "Identical" ||
    reason.applications === "Identical" ||
    reason.ports === "Identical"
      ? "Duplicate"
      : "Shadowed";

  return (
    <Tooltip
      label={<ShadowTooltip shadow={shadow} />}
      color="dark"
      withArrow
      multiline
      w={rem(360)}
      position="bottom-start"
      openDelay={150}
    >
      <Badge
        variant="filled"
        color="yellow.7"
        leftSection={<IconAlertTriangle size="0.72rem" />}
        data-interactive="true"
        style={{ cursor: "help", flexShrink: 0 }}
      >
        {label}
      </Badge>
    </Tooltip>
  );
}

function ShadowTooltip({ shadow }: { shadow: EnrichedShadow }) {
  const { reason, shadowerIndex, shadowerName } = shadow;
  return (
    <div style={{ lineHeight: 1.5 }}>
      <div>
        Overshadowed by rule <b>#{shadowerIndex + 1}</b> —{" "}
        <span style={{ fontStyle: "italic" }}>{shadowerName}</span>
      </div>
      <div style={{ marginTop: 4, opacity: 0.8 }}>
        Coverage per field:
      </div>
      <ul style={{ margin: "2px 0 0", paddingLeft: 16 }}>
        <li>
          <b>Targets</b>: {explainField(reason.targets)}
        </li>
        <li>
          <b>Applications</b>: {explainField(reason.applications)}
        </li>
        <li>
          <b>Ports</b>: {explainField(reason.ports)}
        </li>
      </ul>
      <div style={{ marginTop: 4, opacity: 0.75, fontSize: "var(--ppxray-text-caption)" }}>
        This rule will never fire. Reorder, narrow the earlier rule, or
        disable one of the two.
      </div>
    </div>
  );
}

function explainField(f: EnrichedShadow["reason"]["targets"]): string {
  switch (f) {
    case "Any":
      return "earlier rule has no entries (matches everything)";
    case "Identical":
      return "identical to this rule";
    case "Covers":
      return "earlier rule's entries cover this rule's entries";
  }
}

function ListPreview({
  items,
  mono,
  emptyLabel,
}: {
  items: string[];
  mono?: boolean;
  emptyLabel: string;
}) {
  if (items.length === 0) {
    return (
      <Text size="xs" c="dimmed">
        {emptyLabel}
      </Text>
    );
  }
  const preview = items.slice(0, 2).join("; ");
  const more = items.length > 2 ? ` - +${items.length - 2}` : "";
  return (
    <Text
      size="xs"
      className={mono ? "mono" : undefined}
      style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
      title={items.join("\n")}
    >
      {preview}
      {more}
    </Text>
  );
}
