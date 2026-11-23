import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import GuidedCase, { STEPS, jumpTo } from "./GuidedCase.jsx";

let onFilterIp;
beforeEach(() => {
  onFilterIp = vi.fn();
});
afterEach(() => {
  document.body.querySelectorAll("[data-fake]").forEach((n) => n.remove());
});
const show = (props = {}) => render(<GuidedCase onFilterIp={onFilterIp} {...props} />);
const item = (i) => screen.getAllByRole("listitem")[i];

describe("STEPS", () => {
  it("son 7 pasos con título y texto no vacíos y títulos únicos", () => {
    expect(STEPS).toHaveLength(7);
    for (const s of STEPS) {
      expect(s.title.trim()).not.toBe("");
      expect(s.text.trim().length).toBeGreaterThan(30);
    }
    expect(new Set(STEPS.map((s) => s.title)).size).toBe(7);
  });

  it("cada acción tiene etiqueta y exactamente un destino (ip o jump)", () => {
    for (const s of STEPS.filter((x) => x.action)) {
      expect(s.action.label.trim()).not.toBe("");
      expect(Boolean(s.action.ip) !== Boolean(s.action.jump)).toBe(true);
    }
    expect(STEPS.filter((s) => !s.action)).toHaveLength(1); // el último paso es de reflexión
    expect(STEPS.at(-1).action).toBeUndefined();
  });

  it("las IP de las acciones son IPv4 válidas", () => {
    for (const s of STEPS.filter((x) => x.action?.ip)) expect(s.action.ip).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/);
  });

  it("los textos son texto plano (sin marcado HTML)", () => {
    for (const s of STEPS) expect(`${s.title} ${s.text}`).not.toMatch(/<\/?[a-z][^>]*>/i);
  });

  it("los pasos coinciden con los hechos del demo (IP citadas)", () => {
    const all = STEPS.map((s) => s.text).join(" ");
    expect(all).toContain("192.168.1.66");
    expect(all).toContain("192.168.1.20");
    expect(all).toContain("hunter2");
  });
});

describe("jumpTo", () => {
  it("hace scroll suave al elemento con ese id", () => {
    const el = document.createElement("div");
    el.id = "destino-prueba";
    el.setAttribute("data-fake", "1");
    el.scrollIntoView = vi.fn();
    document.body.appendChild(el);
    jumpTo("destino-prueba");
    expect(el.scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
  });

  it("si el id no existe no hace nada ni lanza", () => {
    expect(() => jumpTo("no-existe-xyz")).not.toThrow();
    expect(jumpTo("no-existe-xyz")).toBeUndefined();
  });

  it("si el navegador no tiene scrollIntoView (jsdom) no lanza", () => {
    const el = document.createElement("div");
    el.id = "sin-scroll";
    el.setAttribute("data-fake", "1");
    el.scrollIntoView = undefined;
    document.body.appendChild(el);
    expect(() => jumpTo("sin-scroll")).not.toThrow();
  });
});

describe("GuidedCase", () => {
  it("título, contador inicial y los 7 pasos con su casilla", () => {
    show();
    expect(screen.getByRole("heading", { name: "Caso guiado: investigá este demo" })).toBeInTheDocument();
    expect(screen.getByText("0 de 7 pasos")).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(7);
    for (const s of STEPS) expect(screen.getByText(s.title)).toBeInTheDocument();
  });

  it("tildar un paso actualiza el contador y marca 'done' (tachado por CSS)", async () => {
    show();
    await userEvent.click(screen.getAllByRole("checkbox")[0]);
    expect(screen.getByText("1 de 7 pasos")).toBeInTheDocument();
    expect(item(0).className).toBe("done");
    expect(item(1).className).toBe("");
    await userEvent.click(screen.getAllByRole("checkbox")[4]);
    expect(screen.getByText("2 de 7 pasos")).toBeInTheDocument();
  });

  it("destildar vuelve a bajar el contador", async () => {
    show();
    const box = screen.getAllByRole("checkbox")[2];
    await userEvent.click(box);
    await userEvent.click(box);
    expect(screen.getByText("0 de 7 pasos")).toBeInTheDocument();
    expect(box).not.toBeChecked();
    expect(item(2).className).toBe("");
  });

  it("se pueden tildar los 7", async () => {
    show();
    for (const b of screen.getAllByRole("checkbox")) await userEvent.click(b);
    expect(screen.getByText("7 de 7 pasos")).toBeInTheDocument();
  });

  it("el título está dentro del label de su casilla (clic en el título tilda)", async () => {
    show();
    await userEvent.click(screen.getByText(STEPS[3].title));
    expect(screen.getAllByRole("checkbox")[3]).toBeChecked();
  });

  it("Ocultar / Mostrar con aria-expanded", async () => {
    show();
    const toggle = screen.getByRole("button", { name: "Ocultar" });
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    await userEvent.click(toggle);
    const show2 = screen.getByRole("button", { name: "Mostrar" });
    expect(show2).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
    expect(screen.getByText("0 de 7 pasos")).toBeInTheDocument(); // el contador sigue visible
    await userEvent.click(show2);
    expect(screen.getAllByRole("checkbox")).toHaveLength(7);
  });

  it("ocultar y mostrar no pierde los pasos tildados", async () => {
    show();
    await userEvent.click(screen.getAllByRole("checkbox")[1]);
    await userEvent.click(screen.getByRole("button", { name: "Ocultar" }));
    await userEvent.click(screen.getByRole("button", { name: "Mostrar" }));
    expect(screen.getAllByRole("checkbox")[1]).toBeChecked();
    expect(screen.getByText("1 de 7 pasos")).toBeInTheDocument();
  });

  it("los botones de acción con IP llaman a onFilterIp con esa IP", async () => {
    show();
    for (const s of STEPS.filter((x) => x.action?.ip)) {
      await userEvent.click(screen.getByRole("button", { name: s.action.label }));
      expect(onFilterIp).toHaveBeenLastCalledWith(s.action.ip);
    }
    expect(onFilterIp).toHaveBeenCalledTimes(STEPS.filter((x) => x.action?.ip).length);
  });

  it("los botones de salto hacen scrollIntoView del elemento si existe", async () => {
    show();
    const targets = STEPS.filter((x) => x.action?.jump);
    for (const s of targets) {
      const el = document.createElement("div");
      el.id = s.action.jump;
      el.setAttribute("data-fake", "1");
      el.scrollIntoView = vi.fn();
      document.body.appendChild(el);
      await userEvent.click(screen.getByRole("button", { name: s.action.label }));
      expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
    }
    expect(onFilterIp).not.toHaveBeenCalled();
  });

  it("si el elemento de destino no está, el botón no hace nada ni rompe", async () => {
    show();
    await userEvent.click(screen.getByRole("button", { name: "Ir a DNS" }));
    expect(onFilterIp).not.toHaveBeenCalled();
  });

  it("sin onFilterIp los botones de IP no rompen", async () => {
    show({ onFilterIp: undefined });
    await userEvent.click(screen.getByRole("button", { name: /Filtrar por 192.168.1.66/ }));
  });

  it("el último paso no trae botón de acción", () => {
    show();
    expect(within(item(6)).queryByRole("button")).toBeNull();
  });
});

describe("GuidedCase: onJump", () => {
  it("cada paso con salto declara su sección", () => {
    const map = Object.fromEntries(STEPS.filter((x) => x.action?.jump).map((x) => [x.action.jump, x.action.section]));
    expect(map).toEqual({ "summary-title": "panorama", "alerts-title": "alertas", "httpall-title": "trafico", "dns-title": "trafico" });
  });

  it("con onJump llama onJump(sección, id) y no hace scroll por su cuenta", async () => {
    const onJump = vi.fn();
    const el = document.createElement("div");
    el.id = "dns-title";
    el.setAttribute("data-fake", "1");
    el.scrollIntoView = vi.fn();
    document.body.appendChild(el);
    show({ onJump });
    await userEvent.click(screen.getByRole("button", { name: "Ir a DNS" }));
    expect(onJump).toHaveBeenCalledWith("trafico", "dns-title");
    await userEvent.click(screen.getByRole("button", { name: "Ir al resumen" }));
    expect(onJump).toHaveBeenLastCalledWith("panorama", "summary-title");
    await userEvent.click(screen.getByRole("button", { name: "Ir a las alertas" }));
    expect(onJump).toHaveBeenLastCalledWith("alertas", "alerts-title");
    await userEvent.click(screen.getByRole("button", { name: "Ir a HTTP" }));
    expect(onJump).toHaveBeenLastCalledWith("trafico", "httpall-title");
    expect(onJump).toHaveBeenCalledTimes(4);
    expect(el.scrollIntoView).not.toHaveBeenCalled();
  });

  it("los pasos con IP siguen usando onFilterIp aunque haya onJump", async () => {
    const onJump = vi.fn();
    show({ onJump });
    await userEvent.click(screen.getByRole("button", { name: "Filtrar por 192.168.1.66" }));
    expect(onFilterIp).toHaveBeenCalledWith("192.168.1.66");
    expect(onJump).not.toHaveBeenCalled();
  });

  it("sin onJump hace scroll como antes", async () => {
    const el = document.createElement("div");
    el.id = "alerts-title";
    el.setAttribute("data-fake", "1");
    el.scrollIntoView = vi.fn();
    document.body.appendChild(el);
    show();
    await userEvent.click(screen.getByRole("button", { name: "Ir a las alertas" }));
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
  });
});
