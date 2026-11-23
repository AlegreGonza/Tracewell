import { describe, it, expect } from "vitest";
import { HINT_LABEL } from "./hints.js";

describe("HINT_LABEL", () => {
  it("cubre los tres códigos de pista que manda el servidor", () => {
    expect(Object.keys(HINT_LABEL).sort()).toEqual(["borrado", "carpeta_temporal", "nombre_de_windows"]);
  });
  it("las etiquetas son textos cortos y planos", () => {
    for (const [code, label] of Object.entries(HINT_LABEL)) {
      expect(label.trim().length, code).toBeGreaterThan(3);
      expect(label.length, code).toBeLessThan(60);
      expect(label, code).not.toMatch(/<\/?[a-z]/i);
    }
  });
});
