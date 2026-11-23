import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { HELP, GLOSSARY } from "./help.js";

const src = path.join(process.cwd(), "src");
const readJsx = (d) => fs.readdirSync(d).filter((f) => f.endsWith(".jsx") && !f.includes(".test.")).map((f) => [f, fs.readFileSync(path.join(d, f), "utf8")]);
// Todas las pantallas y componentes
const all = ["views", "components/captures", "components/common", "components/support"].flatMap((d) => readJsx(path.join(src, d)));
const roots = ["App.jsx", "main.jsx"].map((f) => fs.readFileSync(path.join(src, f), "utf8"));
// Solo cuentan los componentes que de verdad se usan
const sources = all.filter(([f]) => [...roots, ...all.filter(([g]) => g !== f).map(([, t]) => t)].some((t) => t.includes(`/${f}"`)));

describe("HELP", () => {
  it("cada tema tiene title y text no vacíos y ninguna clave wireshark", () => {
    expect(Object.keys(HELP).length).toBeGreaterThan(5);
    for (const [id, h] of Object.entries(HELP)) {
      expect(typeof h.title, id).toBe("string");
      expect(h.title.trim(), id).not.toBe("");
      expect(typeof h.text, id).toBe("string");
      expect(h.text.trim().length, id).toBeGreaterThan(20);
      expect("wireshark" in h, id).toBe(false);
    }
  });

  it("los ids son slugs simples", () => {
    for (const id of Object.keys(HELP)) expect(id).toMatch(/^[a-z][a-z0-9_]*$/);
  });

  it("los títulos son únicos (cada botón de ayuda se distingue por su aria-label)", () => {
    const titles = Object.values(HELP).map((h) => h.title);
    expect(new Set(titles).size).toBe(titles.length);
  });

  it("ningún texto contiene marcado HTML", () => {
    for (const [id, h] of Object.entries(HELP)) {
      for (const v of [h.title, h.text]) expect(v, id).not.toMatch(/<\/?[a-z][^>]*>/i);
    }
  });

  it("todo tema usado con <HelpTip topic=...> en los componentes existe en help.js", () => {
    const used = [];
    for (const [file, src] of sources) {
      for (const m of src.matchAll(/<HelpTip\s+topic=(?:"([^"]+)"|\{["']([^"']+)["']\})/g)) used.push([file, m[1] ?? m[2]]);
    }
    expect(used.length).toBeGreaterThanOrEqual(10);
    for (const [file, topic] of used) expect(HELP[topic], `${file} usa el tema inexistente "${topic}"`).toBeDefined();
  });

  it("no queda ningún tema sin usar (ayuda huérfana)", () => {
    const all = sources.map(([, s]) => s).join("\n");
    const orphan = Object.keys(HELP).filter((id) => !all.includes(`"${id}"`));
    expect(orphan).toEqual([]);
  });
});

describe("GLOSSARY", () => {
  it("son pares [término, texto] no vacíos", () => {
    expect(GLOSSARY.length).toBeGreaterThan(10);
    for (const entry of GLOSSARY) {
      expect(entry).toHaveLength(2);
      expect(entry[0].trim()).not.toBe("");
      expect(entry[1].trim().length).toBeGreaterThan(10);
    }
  });

  it("los términos son únicos (sin distinguir mayúsculas)", () => {
    const terms = GLOSSARY.map(([t]) => t.toLowerCase());
    expect(new Set(terms).size).toBe(terms.length);
  });

  it("ningún texto contiene marcado HTML", () => {
    for (const [t, d] of GLOSSARY) expect(`${t} ${d}`).not.toMatch(/<\/?[a-z][^>]*>/i);
  });
});

describe("temas del Soporte de red", () => {
  it("existen los seis temas del Sistema y los usan los componentes de support/", () => {
    const ids = ["sistema_resumen", "sistema_procesos", "sistema_puertos", "sistema_conexiones", "sistema_servicios", "sistema_inicio"];
    const supportSrc = readJsx(path.join(src, "components", "support")).map(([, t]) => t).join("\n");
    for (const id of ids) {
      expect(HELP[id], id).toBeDefined();
      expect(supportSrc).toContain(`topic="${id}"`);
    }
  });

  it("los términos nuevos del glosario no repiten los de antes (términos únicos, sin distinguir mayúsculas)", () => {
    const terms = GLOSSARY.map(([t]) => t.toLowerCase());
    expect(new Set(terms).size).toBe(terms.length);
  });

  it("ningún tema del Soporte promete acciones que no existen (terminar, desactivar, borrar)", () => {
    for (const [id, h] of Object.entries(HELP).filter(([k]) => k.startsWith("sistema_"))) {
      expect(`${h.title} ${h.text}`, id).not.toMatch(/hac[ée] clic en (terminar|desactivar|borrar)/i);
    }
  });
});
