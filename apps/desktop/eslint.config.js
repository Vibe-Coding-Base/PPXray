// Flat ESLint config.
//
// `tsc --noEmit` already covers types, so this is deliberately narrow: it
// exists for the class of bug TypeScript cannot see — stale hook
// dependencies. A `useMemo` keyed on a value that is rebuilt every render
// silently does nothing, and the UI then shows work it thinks it skipped.
// In a tool whose job is reporting what your machine is doing *now*, that is
// a correctness bug, not a style one.
//
// Only errors fail `pnpm lint`. What is an error and what is a warning is a
// deliberate split, documented per rule below.

import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "eslint.config.js"] },
  js.configs.recommended,
  tseslint.configs.recommended,

  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // The two that block a merge. Both catch real defects that survive
      // type-checking.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",

      // Advisory. These three fire on patterns this codebase uses
      // deliberately and correctly, so treating them as errors would mean
      // rewriting working components to satisfy the linter:
      //
      // * set-state-in-effect — seeding a form when a modal opens, and
      //   resetting a local draft when the value behind it changes. There is
      //   no `key` to hang that on, and the alternatives are worse.
      // * refs — dnd-kit's `useSortable` hands back `attributes` and
      //   `listeners` that its own documentation says to spread during
      //   render.
      // * static-components — fires on `const Icon = iconFor(severity)`,
      //   which selects between module-level icon components rather than
      //   creating one.
      //
      // Left on as warnings so a genuinely new instance is still visible.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/refs": "warn",
      "react-hooks/static-components": "warn",

      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],

      // Underscore prefix is the documented way to say "unused on purpose".
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],

      // IPC payloads cross a Rust/TS boundary where a cast is occasionally
      // the honest option; `@ppxray/ipc-schema` is the real type contract.
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },

  {
    // Each store file deliberately exports its Provider next to the hooks
    // that read it, so the context and its accessors stay together. The cost
    // is a full reload instead of a fast refresh when a store changes.
    files: ["src/stores/**"],
    rules: { "react-refresh/only-export-components": "off" },
  },

  {
    files: ["**/*.cjs"],
    languageOptions: { sourceType: "commonjs", globals: globals.node },
  },
);
