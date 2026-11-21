import { createTheme } from "@mantine/core";

// Escalas de acento de cada paleta (10 tonos). El tono 6 (claro) y el 4 (oscuro) son los mismos del acento de tokens.css.
const SCALES = {
  esmeralda: ["#ecfdf5", "#d1fae5", "#a7f3d0", "#6ee7b7", "#34d399", "#10b981", "#059669", "#047857", "#065f46", "#064e3b"],
  violeta: ["#f3f0ff", "#e5dbff", "#d0bfff", "#b197fc", "#8b7cf6", "#7950f2", "#6d4fe0", "#5f3dc4", "#4c2da5", "#3b2380"],
  terracota: ["#fdf1ec", "#fadfd3", "#f3bfa8", "#ea9d7e", "#d97757", "#cf6a46", "#b8512c", "#9a4122", "#7c331a", "#5e2713"],
};

export const PALETTES = [
  { id: "esmeralda", label: "Esmeralda", swatch: "#34d399" },
  { id: "violeta", label: "Violeta", swatch: "#8b7cf6" },
  { id: "terracota", label: "Terracota", swatch: "#d97757" },
];

// Tema de Mantine con la paleta elegida. Las superficies siguen las variables de tokens.css (ver styles.css).
export function buildTheme(palette = "esmeralda") {
  return createTheme({
    primaryColor: "tw",
    primaryShade: { light: 6, dark: 4 },
    colors: { tw: SCALES[palette] ?? SCALES.esmeralda },
    fontFamily: '"Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", system-ui, -apple-system, Roboto, sans-serif',
    fontFamilyMonospace: '"Cascadia Mono", "Cascadia Code", ui-monospace, "SF Mono", Consolas, "Liberation Mono", monospace',
    defaultRadius: "md",
    fontSizes: { xs: "0.72rem", sm: "0.82rem", md: "0.9rem", lg: "1rem", xl: "1.2rem" },
    headings: { fontWeight: "600" },
  });
}

export const theme = buildTheme();
