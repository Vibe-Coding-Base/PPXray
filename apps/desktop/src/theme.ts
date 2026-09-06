import { createTheme, type MantineColorsTuple } from "@mantine/core";

// Dense, desk-tool dark theme. Tuned for network telemetry: calm slate base,
// cool accent, reserved reds/yellows for severity.
const accent: MantineColorsTuple = [
  "#e7f5ff",
  "#d0ebff",
  "#a5d8ff",
  "#74c0fc",
  "#4dabf7",
  "#339af0",
  "#228be6",
  "#1c7ed6",
  "#1971c2",
  "#1864ab",
];

export const theme = createTheme({
  primaryColor: "blue",
  primaryShade: { light: 6, dark: 5 },
  defaultRadius: "sm",
  // Both read the CSS variables that `stores/ui-prefs.ts` writes onto <html>,
  // so the Settings controls reach Mantine components and plain elements
  // alike rather than only the latter.
  fontFamily: "var(--ppxray-font)",
  fontFamilyMonospace: "var(--mono)",
  /*
   * A compressed body scale.
   *
   * This app uses `xs` as its body size in about 250 places - it was written
   * as a dense desk tool - while Settings uses `sm`. On Mantine's default
   * scale those are 0.75rem and 0.875rem, a 17% step, so moving between
   * Settings and any other module looked like the text size changed. Here
   * they are within 7% of each other: near enough to read as one size, while
   * `md` and up still give headings somewhere to go.
   *
   * `--ppxray-text-dense` in global.css matches `xs`, so tables and prose
   * agree too.
   */
  fontSizes: {
    xs: "0.82rem",
    sm: "0.88rem",
    md: "1rem",
    lg: "1.15rem",
    xl: "1.3rem",
  },
  headings: {
    fontWeight: "600",
  },
  colors: {
    blue: accent,
  },
  components: {
    // `xs` controls came out ~26px tall, which is a small target even for a
    // dense tool. One step up across the board; anything that genuinely needs
    // to be tiny still passes its own `size`.
    Button: {
      defaultProps: { size: "sm" },
    },
    ActionIcon: {
      defaultProps: { size: "lg", variant: "subtle" },
    },
    Table: {
      defaultProps: { verticalSpacing: 4, horizontalSpacing: "sm" },
    },
    // Badge, Chip and the compact Button variants size themselves from their
    // own ramps rather than from `fontSizes`, so their `xs` is a fixed
    // 0.625rem and stays there however large the interface is set. Defaulting
    // them a step up keeps chips legible beside `sm` body text.
    // `md` because Badge's own ramp runs smaller than the body scale: its
    // `sm` is 0.75rem against 0.88rem for `Text size="sm"`, so a chip beside
    // a sentence read as shrunken even after the sizes were unified. `md` is
    // 0.875rem, which lines up.
    Badge: {
      defaultProps: { size: "md" },
    },
    Chip: {
      defaultProps: { size: "md" },
    },
  },
});
