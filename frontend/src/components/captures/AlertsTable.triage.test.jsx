import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: {
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), alerts: vi.fn() } }));
import { api } from "../../api/client.js";
import AlertsTable from "./AlertsTable.jsx";

const alert = (over = {}) => ({
  rule_id: "R1",
  name: "Escaneo",
  severity: "high",
  mitre_technique: "T1046",
  mitre_name: "NSD",
  mitre_tactic: "Discovery",
  description: "d",
  src_ip: "10.0.0.5",
  dst_ip: "8.8.8.8",
  first_ts: 1700000000,
  evidence: {},
  ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.alerts.mockResolvedValue([alert(), alert({ rule_id: "R2", name: "Otra", src_ip: "192.168.1.66" })]);
});

describe("AlertsTable: Ver las sesiones", () => {
  it("el botón aparece solo dentro de la alerta expandida", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} onViewSessions={vi.fn()} />);
    await screen.findByRole("button", { name: /Escaneo/ });
    expect(screen.queryByRole("button", { name: /Ver las sesiones/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Escaneo/ }));
    expect(screen.getByRole("button", { name: "Ver las sesiones de 10.0.0.5" })).toBeInTheDocument();
  });

  it("al pulsarlo llama onViewSessions con la alerta completa", async () => {
    const onView = vi.fn();
    render(<AlertsTable refreshKey={0} onError={onError} onViewSessions={onView} />);
    await userEvent.click(await screen.findByRole("button", { name: /Otra/ }));
    await userEvent.click(screen.getByRole("button", { name: "Ver las sesiones de 192.168.1.66" }));
    expect(onView).toHaveBeenCalledTimes(1);
    expect(onView.mock.calls[0][0]).toMatchObject({ rule_id: "R2", src_ip: "192.168.1.66" });
  });

  it("sin la prop onViewSessions no hay botón", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    expect(screen.queryByRole("button", { name: /Ver las sesiones/ })).toBeNull();
  });

  it("cada alerta expandida usa su propia IP; expandir otra cierra la anterior", async () => {
    render(<AlertsTable refreshKey={0} onError={onError} onViewSessions={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    await userEvent.click(screen.getByRole("button", { name: /Otra/ }));
    expect(screen.queryByRole("button", { name: "Ver las sesiones de 10.0.0.5" })).toBeNull();
    expect(screen.getByRole("button", { name: "Ver las sesiones de 192.168.1.66" })).toBeInTheDocument();
  });

  it("una IP con marcado HTML se muestra como texto", async () => {
    api.alerts.mockResolvedValue([alert({ src_ip: "<b>x</b>" })]);
    const { container } = render(<AlertsTable refreshKey={0} onError={onError} onViewSessions={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    const btn = screen.getByRole("button", { name: "Ver las sesiones de <b>x</b>" });
    expect(within(btn).queryByText("x")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
  });
});
