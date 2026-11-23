import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: {
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), alerts: vi.fn() } }));
import { api } from "../../api/client.js";
import AlertsTable from "./AlertsTable.jsx";

const alert = (over = {}) => ({
  rule_id: "R1",
  name: "DNS tunneling",
  severity: "high",
  mitre_technique: "T1071.004",
  mitre_name: "DNS",
  mitre_tactic: "Command and Control",
  description: "Muchas consultas TXT largas",
  src_ip: "10.0.0.5",
  dst_ip: "8.8.8.8",
  first_ts: 1700000000,
  evidence: { queries: 120 },
  ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.alerts.mockResolvedValue([alert(), alert({ rule_id: "R2", name: "Port scan", severity: "low", mitre_technique: "T1046" })]);
});

describe("AlertsTable", () => {
  it("lista las alertas con severidad en texto", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} />);
    expect(screen.getByText("Cargando…")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /DNS tunneling/ })).toHaveTextContent("Alta");
    expect(screen.getByRole("button", { name: /Port scan/ })).toHaveTextContent("Baja");
    expect(screen.getByRole("button", { name: /DNS tunneling/ })).toHaveTextContent("10.0.0.5 → 8.8.8.8");
    expect(api.alerts).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
  });

  it("estado vacío", async () => {
    api.alerts.mockResolvedValue([]);
    render(<AlertsTable refreshKey={0} onError={onError} />);
    expect(await screen.findByText("No hay alertas.")).toBeInTheDocument();
  });

  it("filtro de severidad llama a api.alerts con el valor", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} />);
    await screen.findByText("DNS tunneling");
    api.alerts.mockResolvedValue([]);
    await userEvent.selectOptions(screen.getByLabelText("Severidad"), "critical");
    expect(await screen.findByText("No hay alertas con esa severidad.")).toBeInTheDocument();
    expect(api.alerts.mock.calls.at(-1)[0]).toBe("critical");
  });

  it("expandir muestra descripción, MITRE y link correcto (T1071.004 -> /T1071/004/)", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} />);
    const row = await screen.findByRole("button", { name: /DNS tunneling/ });
    expect(row).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Muchas consultas TXT largas")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "T1071.004" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1071/004/");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    expect(screen.getByText(/Command and Control/)).toBeInTheDocument();
    // volver a clickear colapsa
    await userEvent.click(row);
    expect(screen.queryByText("Muchas consultas TXT largas")).toBeNull();
  });

  it("técnica sin sub-técnica -> /T1046/", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} />);
    await userEvent.click(await screen.findByRole("button", { name: /Port scan/ }));
    expect(screen.getByRole("link", { name: "T1046" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1046/");
  });

  it("la evidencia hostil se muestra como TEXTO (sin img ni ejecución)", async () => {
    const alertSpy = vi.fn();
    vi.stubGlobal("alert", alertSpy);
    api.alerts.mockResolvedValue([alert({ evidence: { host: "<img src=x onerror=alert(1)>" }, description: "d" })]);
    const { container } = render(<AlertsTable refreshKey={0} onError={onError} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("pre").textContent).toContain("<img src=x onerror=alert(1)>");
    expect(alertSpy).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("error de API llama onError con el mensaje", async () => {
    api.alerts.mockRejectedValue(new Error("boom"));
    render(<AlertsTable refreshKey={0} onError={onError} />);
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("boom"));
  });

  it("AbortError no llama onError", async () => {
    api.alerts.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    render(<AlertsTable refreshKey={0} onError={onError} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(onError).not.toHaveBeenCalled();
  });

  it("cambiar refreshKey vuelve a pedir las alertas", async () => {
    const { rerender } = render(<AlertsTable refreshKey={0} onError={onError} />);
    await screen.findByText("DNS tunneling");
    rerender(<AlertsTable refreshKey={1} onError={onError} />);
    await vi.waitFor(() => expect(api.alerts).toHaveBeenCalledTimes(2));
  });
});

describe("AlertsTable: filtro de Wireshark", () => {
  it("la alerta expandida ofrece copiar su filtro", async () => {
    const writeText = vi.fn().mockResolvedValue();
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    api.alerts.mockResolvedValue([alert({ wireshark_filter: "ip.addr==10.0.0.5 && ip.addr==8.8.8.8" })]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    await userEvent.click(screen.getByRole("button", { name: "Copiar filtro Wireshark" }));
    expect(writeText).toHaveBeenCalledWith("ip.addr==10.0.0.5 && ip.addr==8.8.8.8");
  });

  it("sin filtro en la alerta no muestra el botón", async () => {
    api.alerts.mockResolvedValue([alert()]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(screen.queryByRole("button", { name: "Copiar filtro Wireshark" })).toBeNull();
  });
});

describe("AlertsTable: guía de la regla", () => {
  const guide = {
    false_positives: ["Escáner autorizado"],
    investigation_steps: ["Ver las sesiones del origen", "Abrir el filtro en Wireshark"],
    wireshark_filter: "tcp.flags.syn==1 && tcp.flags.ack==0",
  };

  it("muestra falsos positivos, pasos y filtro de la regla", async () => {
    api.alerts.mockResolvedValue([alert({ guide })]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(screen.getByRole("heading", { name: "Posibles falsos positivos" })).toBeInTheDocument();
    expect(screen.getByText("Escáner autorizado")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Cómo investigarla" })).toBeInTheDocument();
    expect(screen.getAllByRole("listitem").some((li) => li.textContent === "Abrir el filtro en Wireshark")).toBe(true);
    expect(screen.getByText("tcp.flags.syn==1 && tcp.flags.ack==0")).toBeInTheDocument();
  });

  it("sin guía no muestra esas secciones", async () => {
    api.alerts.mockResolvedValue([alert()]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(screen.queryByText("Posibles falsos positivos")).toBeNull();
    expect(screen.queryByText("Cómo investigarla")).toBeNull();
  });

  it("muestra solo las partes que la regla define", async () => {
    api.alerts.mockResolvedValue([alert({ guide: { investigation_steps: ["Paso único"] } })]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(screen.getByText("Paso único")).toBeInTheDocument();
    expect(screen.queryByText("Posibles falsos positivos")).toBeNull();
  });

  it("el texto de la guía no se interpreta como HTML", async () => {
    api.alerts.mockResolvedValue([alert({ guide: { false_positives: ["<img src=x onerror=alert(1)>"] } })]);
    render(<AlertsTable refreshKey={0} onError={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /DNS tunneling/ }));
    expect(document.querySelector("img")).toBeNull();
  });
});
