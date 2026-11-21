import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({
  api: {
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(), timeline: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"), closeCapture: vi.fn(),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
    sessionPcapUrl: vi.fn(), filteredPcapUrl: vi.fn(), hosts: vi.fn(), graph: vi.fn(), dns: vi.fn(), explain: vi.fn(),
    sessionHttp: vi.fn(), sessionTls: vi.fn(), httpOverview: vi.fn(), httpBodyUrl: vi.fn(),
  },
}));
import { api } from "../../api/client.js";
import CapturesView from "../../views/CapturesView.jsx";
import EmptySection, { EMPTY_SECTIONS } from "./EmptySection.jsx";

const TITLES = {
  alertas: "Alertas y ATT&CK", equipos: "Equipos", trafico: "DNS y HTTP", sesiones: "Sesiones", indicadores: "Indicadores (IOC)",
};

describe("EmptySection", () => {
  it.each(Object.entries(TITLES))("%s: título y texto", (section, title) => {
    render(<EmptySection section={section} onDemo={() => {}} onHome={() => {}} />);
    expect(screen.getByRole("heading", { level: 2, name: title })).toBeInTheDocument();
    expect(screen.getByText(/Todavía no hay una captura cargada\. Cuando cargues una, acá vas a ver/)).toBeInTheDocument();
    expect(EMPTY_SECTIONS[section].title).toBe(title);
  });

  it("«Cargar el ejemplo» llama a onDemo y «Abrir un archivo o capturar» a onHome", async () => {
    const onDemo = vi.fn();
    const onHome = vi.fn();
    render(<EmptySection section="equipos" onDemo={onDemo} onHome={onHome} />);
    await userEvent.click(screen.getByRole("button", { name: "Cargar el ejemplo" }));
    expect(onDemo).toHaveBeenCalledTimes(1);
    expect(onHome).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Abrir un archivo o capturar" }));
    expect(onHome).toHaveBeenCalledTimes(1);
  });

  it.each(["constructor", "__proto__", "xyz"])("sección desconocida «%s» no dibuja nada", (section) => {
    const { container } = render(<EmptySection section={section} onDemo={() => {}} onHome={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("CapturesView sin captura en «equipos»", () => {
  const setup = (props) => {
    vi.clearAllMocks();
    api.capture.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
    api.interfaces.mockResolvedValue([]);
    api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
    api.demo.mockRejectedValue(new Error("stop"));
    render(<CapturesView section="equipos" {...props} />);
  };

  it("«Cargar el ejemplo» llama a api.demo", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    expect(api.demo).toHaveBeenCalled();
  });

  it("«Abrir un archivo o capturar» llama a onNavigate('panorama')", async () => {
    const onNavigate = vi.fn();
    setup({ onNavigate });
    await userEvent.click(await screen.findByRole("button", { name: "Abrir un archivo o capturar" }));
    expect(onNavigate).toHaveBeenCalledWith("panorama");
  });
});
