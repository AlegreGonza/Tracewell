import { StrictMode, useMemo } from "react";
import { createRoot } from "react-dom/client";
import { MantineProvider } from "@mantine/core";
import "@mantine/core/styles.css";
import "@mantine/charts/styles.css";
import { buildTheme } from "./theme.js";
import { usePalette } from "./controllers/usePalette.js";
import App from "./App.jsx";
import ErrorBoundary from "./components/common/ErrorBoundary.jsx";
import "./tokens.css";
import "./styles.css";
import "./shell.css";

// Raíz: elige la paleta de color (se recuerda) y arma el tema de Mantine; el modo claro/oscuro lo maneja Mantine ("auto" = el del sistema).
function Root() {
  const [palette, setPalette] = usePalette();
  const theme = useMemo(() => buildTheme(palette), [palette]);
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <ErrorBoundary>
        <App palette={palette} onPalette={setPalette} />
      </ErrorBoundary>
    </MantineProvider>
  );
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
