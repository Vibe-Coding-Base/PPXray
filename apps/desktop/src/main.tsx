import React from "react";
import ReactDOM from "react-dom/client";

import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@mantine/spotlight/styles.css";
import "./styles/global.css";

import { App } from "./App";
import { applyPrefs, loadPrefs } from "./stores/ui-prefs";

// Before the first render, not in an effect: an effect runs after mount, so
// every reader would see one frame at the default size before it snapped to
// theirs.
applyPrefs(loadPrefs());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
