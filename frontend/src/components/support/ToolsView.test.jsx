import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within, act, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({
  api: {
    supportPing: vi.fn(), supportTraceroute: vi.fn(), supportPorts: vi.fn(), supportRdp: vi.fn(), supportTime: vi.fn(), supportDuplicateIp: vi.fn(),
  },
}));
import { api } from "../../api/client.js";
import ToolsView from "./ToolsView.jsx";

const tool = (title) => within(screen.getByRole("heading", { name: title }).closest("article"));
const type = (t, label, text) => userEvent.type(t.getByLabelText(label), text);

beforeEach(() => {
  vi.clearAllMocks();
  api.supportPing.mockResolvedValue({ available: true, host: "h", sent: 4, received: 3, loss_pct: 25, avg: 12.5, min: 10, max: 15, times: [10, 12, 15] });
});
afterEach(() => vi.useRealTimers());

describe("ToolsView: ping", () => {
  it("hace un ping de 4 y muestra el resumen", async () => {
    render(<ToolsView />);
    const t = tool("Ping");
    expect(t.getByRole("button", { name: "Hacer ping (4)" })).toBeDisabled();
    await type(t, "Equipo o IP", "192.168.1.1");
    await userEvent.click(t.getByRole("button", { name: "Hacer ping (4)" }));
    expect(await t.findByText(/3 de 4 respuestas \(25 % perdido\)/)).toBeInTheDocument();
    expect(api.supportPing.mock.calls[0].slice(0, 2)).toEqual(["192.168.1.1", 4]);
    expect(t.getByText(/promedio 12.5 ms/)).toBeInTheDocument();
  });

  it("sin respuesta y comando no disponible", async () => {
    api.supportPing.mockResolvedValueOnce({ available: true, host: "h", sent: 4, received: 0, loss_pct: 100, avg: null, min: null, max: null, times: [] });
    render(<ToolsView />);
    const t = tool("Ping");
    await type(t, "Equipo o IP", "x");
    await userEvent.click(t.getByRole("button", { name: "Hacer ping (4)" }));
    expect(await t.findByText(/sin respuesta/)).toBeInTheDocument();
    api.supportPing.mockResolvedValueOnce({ available: false, reason: "No se encontró el comando ping." });
    await userEvent.click(t.getByRole("button", { name: "Hacer ping (4)" }));
    expect(await t.findByText("No se encontró el comando ping.")).toBeInTheDocument();
  });

  it("un 422 de la API se muestra como alerta", async () => {
    api.supportPing.mockRejectedValue(new Error("el nombre o la IP no es válido"));
    render(<ToolsView />);
    const t = tool("Ping");
    await type(t, "Equipo o IP", "a;b");
    await userEvent.click(t.getByRole("button", { name: "Hacer ping (4)" }));
    expect(await t.findByRole("alert")).toHaveTextContent("no es válido");
  });

  describe("ping continuo (timers falsos)", () => {
    // Con timers falsos, userEvent necesita advanceTimers
    const start = async () => {
      render(<ToolsView />);
      const t = tool("Ping");
      fireEvent.change(t.getByLabelText("Equipo o IP"), { target: { value: "8.8.8.8" } });
      fireEvent.click(t.getByLabelText(/Ping continuo/));
      await act(async () => {});
      return t;
    };

    it("hace uno enseguida y luego 1 por segundo, con host y count=1", async () => {
      vi.useFakeTimers();
      api.supportPing.mockResolvedValue({ available: true, received: 1, avg: 9 });
      await start();
      expect(api.supportPing).toHaveBeenCalledTimes(1);
      expect(api.supportPing).toHaveBeenCalledWith("8.8.8.8", 1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(api.supportPing).toHaveBeenCalledTimes(4);
      expect(screen.getByText(/4 pings · 0 sin respuesta/)).toBeInTheDocument();
    });

    it("tope de 60 en el historial; los fallos cuentan como sin respuesta", async () => {
      vi.useFakeTimers();
      api.supportPing.mockResolvedValueOnce({ available: true, received: 0, avg: null }).mockResolvedValue({ available: true, received: 1, avg: 5 });
      await start();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(70_000);
      });
      expect(screen.getByText(/^60 pings · \d+ sin respuesta/)).toBeInTheDocument();
      expect(document.querySelectorAll(".pinglog li").length).toBe(60);
    });

    it("al desmarcar deja de pedir; un error de red cuenta como sin respuesta", async () => {
      vi.useFakeTimers();
      api.supportPing.mockRejectedValue(new Error("caída"));
      const t = await start();
      expect(screen.getByText(/1 pings · 1 sin respuesta/)).toBeInTheDocument();
      fireEvent.click(t.getByLabelText(/Ping continuo/));
      const n = api.supportPing.mock.calls.length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(api.supportPing.mock.calls.length).toBe(n);
    });
  });
});

describe("ToolsView: traceroute, puertos, RDP, hora, IP duplicada", () => {
  it("tracert muestra saltos, sin respuesta y razón si falta el comando", async () => {
    api.supportTraceroute.mockResolvedValueOnce({ available: true, hops: [{ n: 1, ips: ["192.168.1.1"], times: [0.5, 1], timeouts: 0 }, { n: 2, ips: [], times: [], timeouts: 3 }] });
    render(<ToolsView />);
    const t = tool("Traza de ruta (tracert)");
    await type(t, "Destino", "www.google.com");
    await userEvent.click(t.getByRole("button", { name: "Trazar" }));
    expect(await t.findByText("192.168.1.1")).toBeInTheDocument();
    expect(t.getByText("0.5 ms · 1 ms")).toBeInTheDocument();
    expect(t.getByText("sin respuesta")).toBeInTheDocument();
    expect(api.supportTraceroute.mock.calls[0][0]).toBe("www.google.com");
    api.supportTraceroute.mockResolvedValueOnce({ available: false, reason: "No se encontró tracert" });
    await userEvent.click(t.getByRole("button", { name: "Trazar" }));
    expect(await t.findByText("No se encontró tracert")).toBeInTheDocument();
  });

  it("puertos: manda los puertos tal cual y muestra estados", async () => {
    api.supportPorts.mockResolvedValue({ host: "h", results: [
      { port: 22, service: "SSH", state: "cerrado", ms: null, detail: null },
      { port: 80, service: "HTTP", state: "abierto", ms: 3.2, detail: null },
      { port: 81, service: null, state: "sin_respuesta", ms: null, detail: null },
    ] });
    render(<ToolsView />);
    const t = tool("Puertos de un equipo");
    await type(t, "Equipo o IP", "10.0.0.2");
    await userEvent.click(t.getByRole("button", { name: "Probar" }));
    expect(await t.findByText(/22 \(SSH\)/)).toBeInTheDocument();
    expect(api.supportPorts.mock.calls[0].slice(0, 2)).toEqual(["10.0.0.2", "22,80,443,3389"]);
    expect(t.getByText("abierto")).toBeInTheDocument();
    expect(t.getByText("sin respuesta (¿filtrado?)")).toBeInTheDocument();
    expect(t.getByText(/3.2 ms/)).toBeInTheDocument();
  });

  it("RDP: puerto 3389 y resumen", async () => {
    api.supportRdp.mockResolvedValue({ state: "rdp", nla: true, summary: "RDP disponible. NLA (CredSSP)" });
    render(<ToolsView />);
    const t = tool("Acceso remoto (RDP)");
    await type(t, "Equipo o IP", "10.0.0.2");
    await userEvent.click(t.getByRole("button", { name: "Probar RDP" }));
    expect(await t.findByText(/RDP disponible/)).toBeInTheDocument();
    expect(api.supportRdp.mock.calls[0].slice(0, 2)).toEqual(["10.0.0.2", 3389]);
  });

  it("hora: ofrece 3 servidores, usa el elegido, muestra la diferencia y el comando solo como texto", async () => {
    api.supportTime.mockResolvedValue({ available: true, server: "pool.ntp.org", offset_seconds: 12.5, round_trip_ms: 20, summary: "El reloj está desfasado.", command: "w32tm /resync" });
    render(<ToolsView />);
    const t = tool("Hora de la PC");
    const select = t.getByRole("combobox");
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["time.windows.com", "pool.ntp.org", "time.cloudflare.com"]);
    await userEvent.selectOptions(select, "pool.ntp.org");
    await userEvent.click(t.getByRole("button", { name: "Comprobar hora" }));
    expect(await t.findByText(/Diferencia: \+12.5 s/)).toBeInTheDocument();
    expect(api.supportTime.mock.calls[0][0]).toBe("pool.ntp.org");
    expect(t.getByText("w32tm /resync").tagName).toBe("CODE");
    expect(t.getAllByRole("button").map((b) => b.textContent)).toEqual(["Comprobar hora"]);
  });

  it("hora no disponible muestra la razón", async () => {
    api.supportTime.mockResolvedValue({ available: false, reason: "No se pudo consultar la hora" });
    render(<ToolsView />);
    await userEvent.click(tool("Hora de la PC").getByRole("button", { name: "Comprobar hora" }));
    expect(await screen.findByText("No se pudo consultar la hora")).toBeInTheDocument();
  });

  it("IP duplicada: duplicado con consejo y MACs; sonda no disponible con razón", async () => {
    api.supportDuplicateIp.mockResolvedValueOnce({
      summary: "¡Otro equipo está usando la misma IP!", duplicate: true, advice: "Cambiá la IP fija de uno de los dos.",
      probes: [{ adapter: "Ethernet", ip: "192.168.1.10", probed: true, duplicate: true, other_macs: ["aa:bb:cc:dd:ee:ff"] }],
      conflicts: [{ time: "2026-01-01T10:00:00+00:00", message: "conflicto" }],
    });
    render(<ToolsView />);
    const t = tool("IP duplicada");
    await userEvent.click(t.getByRole("button", { name: "Revisar" }));
    expect(await t.findByText(/misma IP/)).toBeInTheDocument();
    expect(t.getByText("Cambiá la IP fija de uno de los dos.")).toBeInTheDocument();
    expect(t.getByText(/contestó otra MAC! aa:bb:cc:dd:ee:ff/)).toBeInTheDocument();
    expect(t.getByText(/Aviso de Windows \(2026-01-01 10:00:00\): conflicto/)).toBeInTheDocument();
    api.supportDuplicateIp.mockResolvedValueOnce({ summary: "No se pudo hacer la sonda ARP", duplicate: false, advice: null, conflicts: [], probes: [{ adapter: "Ethernet", ip: "1.2.3.4", probed: false, reason: "hace falta Npcap" }] });
    await userEvent.click(t.getByRole("button", { name: "Revisar" }));
    await waitFor(() => expect(t.getByText(/hace falta Npcap/)).toBeInTheDocument());
  });

  it("textos hostiles (nombres, razones, mensajes) se ven como texto", async () => {
    const evil = "<script>window.__t=1</script>";
    api.supportTraceroute.mockResolvedValue({ available: true, hops: [{ n: 1, ips: [evil], times: [], timeouts: 0 }] });
    api.supportDuplicateIp.mockResolvedValue({ summary: evil, duplicate: false, advice: null, probes: [], conflicts: [{ time: "t", message: evil }] });
    const { container } = render(<ToolsView />);
    await type(tool("Traza de ruta (tracert)"), "Destino", "x");
    await userEvent.click(tool("Traza de ruta (tracert)").getByRole("button", { name: "Trazar" }));
    await userEvent.click(tool("IP duplicada").getByRole("button", { name: "Revisar" }));
    await screen.findAllByText(new RegExp("script"));
    expect(container.querySelector("script")).toBeNull();
    expect(window.__t).toBeUndefined();
  });

  it("no hay ningún botón que modifique el sistema", () => {
    render(<ToolsView />);
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/renovar|liberar|limpiar|flush|release|renew|corregir|sincronizar|ajustar/i);
  });
});
