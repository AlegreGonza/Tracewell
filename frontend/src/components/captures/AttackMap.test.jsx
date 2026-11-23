import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: { alerts: vi.fn() } }));
import { api } from "../../api/client.js";
import AttackMap, { TACTICS, groupByTactic } from "./AttackMap.jsx";

const alert = (over = {}) => ({
  rule_id: "r", name: "n", severity: "medium", mitre_technique: "T1071", mitre_name: "Application Layer Protocol",
  mitre_tactic: "Command and Control", description: "d", src_ip: "1.1.1.1", dst_ip: "2.2.2.2", first_ts: 1, evidence: {}, ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.alerts.mockResolvedValue([]);
});

const show = (props = {}) => render(<AttackMap refreshKey={0} onError={onError} {...props} />);
const column = (container, en) => Array.from(container.querySelectorAll("ol.attack-map > li")).find((li) => li.querySelector(".tactic-en").textContent === en);

describe("TACTICS", () => {
  it("son solo las 5 tácticas que se ven en tráfico de red, en orden", () => {
    expect(TACTICS.map(([n]) => n)).toEqual(["Reconnaissance", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration"]);
    expect(TACTICS.map(([, es]) => es)).toEqual(["Reconocimiento", "Exploración", "Movimiento lateral", "Comando y control", "Exfiltración"]);
    for (const [en, es, gloss] of TACTICS) expect([en.trim(), es.trim(), gloss.trim()].every(Boolean)).toBe(true);
  });

  it("no incluye las tácticas que pasan dentro del equipo", () => {
    const names = TACTICS.map(([n]) => n);
    for (const gone of ["Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Collection", "Impact"]) {
      expect(names).not.toContain(gone);
    }
  });
});

describe("groupByTactic", () => {
  it("lista vacía -> objeto vacío", () => expect(groupByTactic([])).toEqual({}));

  it("agrupa por táctica y técnica y cuenta", () => {
    const g = groupByTactic([alert(), alert(), alert({ mitre_technique: "T1046", mitre_name: "Scan", mitre_tactic: "Discovery" })]);
    expect(Object.keys(g).sort()).toEqual(["Command and Control", "Discovery"]);
    expect(g["Command and Control"].T1071).toEqual({ id: "T1071", name: "Application Layer Protocol", count: 2, severity: "medium" });
    expect(g.Discovery.T1046.count).toBe(1);
  });

  it("conserva la mayor severidad de la técnica, sin importar el orden", () => {
    const a = groupByTactic([alert({ severity: "low" }), alert({ severity: "high" }), alert({ severity: "medium" })]);
    expect(a["Command and Control"].T1071.severity).toBe("high");
    const b = groupByTactic([alert({ severity: "critical" }), alert({ severity: "low" })]);
    expect(b["Command and Control"].T1071.severity).toBe("critical");
    const c = groupByTactic([alert({ severity: "low" }), alert({ severity: "low" })]);
    expect(c["Command and Control"].T1071.severity).toBe("low");
  });

  it("una severidad desconocida no pisa a una conocida", () => {
    const g = groupByTactic([alert({ severity: "low" }), alert({ severity: "weird" })]);
    expect(g["Command and Control"].T1071.severity).toBe("low");
  });

  it("técnicas distintas de la misma táctica quedan separadas", () => {
    const g = groupByTactic([alert(), alert({ mitre_technique: "T1071.004" })]);
    expect(Object.keys(g["Command and Control"]).sort()).toEqual(["T1071", "T1071.004"]);
  });
});

describe("AttackMap", () => {
  it("no dibuja nada mientras carga", () => {
    api.alerts.mockReturnValue(new Promise(() => {}));
    const { container } = show();
    expect(container).toBeEmptyDOMElement();
  });

  it("pide las alertas sin filtro y con una señal de aborto", async () => {
    show();
    await screen.findByRole("heading", { name: /Mapa MITRE/ });
    expect(api.alerts).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
  });

  it("sin alertas: 5 columnas apagadas y el mensaje", async () => {
    const { container } = show();
    expect(await screen.findByText(/Sin alertas: ninguna táctica se iluminó/)).toBeInTheDocument();
    expect(container.querySelectorAll("ol.attack-map > li")).toHaveLength(5);
    expect(container.querySelectorAll("li.tactic.hit")).toHaveLength(0);
    expect(container.querySelectorAll("li.tactic")).toHaveLength(5);
  });

  it("un <li> por táctica; solo las que tienen técnicas llevan 'tactic hit'", async () => {
    api.alerts.mockResolvedValue([alert(), alert({ mitre_technique: "T1046", mitre_name: "Scan", mitre_tactic: "Discovery" })]);
    const { container } = show();
    await screen.findByText(/2 táctica\(s\) con actividad/);
    const lis = Array.from(container.querySelectorAll("ol.attack-map > li"));
    expect(lis).toHaveLength(5);
    expect(lis.filter((l) => l.className === "tactic hit").map((l) => l.querySelector(".tactic-en").textContent)).toEqual(["Discovery", "Command and Control"]);
    expect(lis.filter((l) => l.className === "tactic")).toHaveLength(3);
    expect(within(column(container, "Reconnaissance")).getByText("—")).toBeInTheDocument();
  });

  it("el enlace va a attack.mitre.org con el punto cambiado por barra y rel noopener", async () => {
    api.alerts.mockResolvedValue([
      alert({ mitre_technique: "T1071.004", mitre_name: "DNS" }),
      alert({ mitre_technique: "T1046", mitre_name: "Scan", mitre_tactic: "Discovery" }),
    ]);
    const { container } = show();
    const dns = await screen.findByRole("link", { name: "T1071.004" });
    expect(dns).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1071/004/");
    expect(dns).toHaveAttribute("target", "_blank");
    expect(dns.getAttribute("rel")).toMatch(/noopener/);
    expect(screen.getByRole("link", { name: "T1046" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1046/");
    expect(container.querySelectorAll("a")).toHaveLength(2);
  });

  it("muestra nombre y cantidad por técnica, y la agrupa", async () => {
    api.alerts.mockResolvedValue([alert(), alert(), alert()]);
    const { container } = show();
    await screen.findByRole("link", { name: "T1071" });
    expect(column(container, "Command and Control")).toHaveTextContent("Application Layer Protocol ×3");
    expect(container.querySelectorAll("a")).toHaveLength(1);
    expect(screen.getByRole("link", { name: "T1071" })).toHaveAttribute("title", "Application Layer Protocol · 3 alerta(s)");
  });

  it("una táctica desconocida se agrega al final y no se pierde", async () => {
    api.alerts.mockResolvedValue([alert({ mitre_tactic: "Nueva Táctica", mitre_technique: "T9999", mitre_name: "Rara" })]);
    const { container } = show();
    await screen.findByRole("link", { name: "T9999" });
    const lis = container.querySelectorAll("ol.attack-map > li");
    expect(lis).toHaveLength(6);
    expect(lis[5].className).toBe("tactic hit");
    expect(lis[5]).toHaveTextContent("Nueva Táctica");
    expect(lis[5]).toHaveTextContent("Rara ×1");
  });

  it("una alerta de una táctica que el mapa no lista (p. ej. Credential Access) no se pierde", async () => {
    api.alerts.mockResolvedValue([alert({ mitre_tactic: "Credential Access", mitre_technique: "T1110", mitre_name: "Brute Force" })]);
    const { container } = show();
    await screen.findByRole("link", { name: "T1110" });
    const lis = container.querySelectorAll("ol.attack-map > li");
    expect(lis).toHaveLength(6);
    expect(lis[5]).toHaveTextContent("Credential Access");
  });

  it("varias tácticas desconocidas, cada una en su columna", async () => {
    api.alerts.mockResolvedValue([alert({ mitre_tactic: "X1", mitre_technique: "T1" }), alert({ mitre_tactic: "X2", mitre_technique: "T2" })]);
    const { container } = show();
    await screen.findByRole("link", { name: "T2" });
    expect(container.querySelectorAll("ol.attack-map > li")).toHaveLength(7);
  });

  it("nombres hostiles de táctica, técnica y nombre se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.alerts.mockResolvedValue([alert({ mitre_tactic: evil, mitre_name: evil, mitre_technique: "T1.2" })]);
    const { container } = show();
    await screen.findByRole("link", { name: "T1.2" });
    expect(container.querySelector("img")).toBeNull();
    expect(container).toHaveTextContent(evil);
  });

  it("un id hostil no puede salir del dominio de ATT&CK en el enlace", async () => {
    api.alerts.mockResolvedValue([alert({ mitre_technique: "T1071.004" })]);
    show();
    const a = await screen.findByRole("link", { name: "T1071.004" });
    expect(new URL(a.href).origin).toBe("https://attack.mitre.org");
  });

  it("pie con la cantidad de tácticas con actividad", async () => {
    api.alerts.mockResolvedValue([alert(), alert({ mitre_tactic: "Discovery", mitre_technique: "T1046" })]);
    show();
    expect(await screen.findByText(/2 táctica\(s\) con actividad/)).toBeInTheDocument();
    expect(screen.queryByText(/Sin alertas/)).toBeNull();
  });

  it("tiene su botón de ayuda", async () => {
    show();
    expect(await screen.findByRole("button", { name: /Ayuda: Mapa MITRE/ })).toBeInTheDocument();
  });

  it("un error llama a onError y no dibuja nada", async () => {
    api.alerts.mockRejectedValue(new Error("fallo alertas"));
    const { container } = show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("fallo alertas"));
    expect(container).toBeEmptyDOMElement();
  });

  it("un AbortError no se reporta", async () => {
    api.alerts.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    show();
    await waitFor(() => expect(api.alerts).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
  });

  it("vuelve a pedir si cambia refreshKey, cancelando el pedido viejo", async () => {
    const { rerender } = show();
    await screen.findByRole("heading", { name: /Mapa MITRE/ });
    api.alerts.mockResolvedValue([alert()]);
    rerender(<AttackMap refreshKey={1} onError={onError} />);
    await screen.findByRole("link", { name: "T1071" });
    expect(api.alerts).toHaveBeenCalledTimes(2);
    expect(api.alerts.mock.calls[0][1].aborted).toBe(true);
    rerender(<AttackMap refreshKey={1} onError={onError} />);
    expect(api.alerts).toHaveBeenCalledTimes(2);
  });

  it("al desmontar aborta el pedido en curso", () => {
    api.alerts.mockReturnValue(new Promise(() => {}));
    const { unmount } = show();
    const signal = api.alerts.mock.calls[0][1];
    unmount();
    expect(signal.aborted).toBe(true);
  });
});
