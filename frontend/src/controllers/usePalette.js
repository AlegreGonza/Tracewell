import { useCallback, useEffect, useState } from "react";

const KEY = "tracewell-palette";
const VALID = ["esmeralda", "violeta", "terracota"];

// El almacenamiento del navegador puede fallar (ventana privada, bloqueado)
const read = () => {
  try {
    const v = window.localStorage.getItem(KEY);
    return VALID.includes(v) ? v : "esmeralda";
  } catch {
    return "esmeralda";
  }
};

// Paleta de color elegida
export function usePalette() {
  const [palette, setPaletteState] = useState(read);

  useEffect(() => {
    document.documentElement.setAttribute("data-palette", palette);
  }, [palette]);

  const setPalette = useCallback((next) => {
    if (!VALID.includes(next)) return;
    setPaletteState(next);
    try {
      window.localStorage.setItem(KEY, next);
    } catch {
      /* sin almacenamiento: la elección vale solo para esta sesión */
    }
  }, []);

  return [palette, setPalette];
}
