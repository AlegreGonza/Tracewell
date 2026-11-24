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
import { initToken } from "./api/token.js";

// Raíz: elige la paleta de color (se recuerda) y arma el tema de Mantine
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

// El token tiene que estar antes de la primera llamada a la API.
initToken().finally(() =>
  createRoot(document.getElementById("root")).render(
    <StrictMode>
      <Root />
    </StrictMode>,
  ),
);
