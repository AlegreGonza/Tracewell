import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { rules: vi.fn(), previewRule: vi.fn(), saveRule: vi.fn() } }));
import { api } from "../../api/client.js";
import RulesPanel, { toBody } from "./RulesPanel.jsx";

const EXAMPLE = {
  name: "Muchas conexiones a SSH interno", severity: "high", description: "Una IP intentó conectarse muchas veces.",
  protocol: "tcp", src_ip: "", dst_ip: "10.0.0.0/8", port: 22, min_events: 8, window_seconds: 30,
};
const PREVIEW = {
  id: "mi_regla", yaml: "id: mi_regla\nname: Mi regla\n", exists: false,
  matches: { sessions: 12, alerts: 2, sample: [{ src_ip: "1.1.1.1", dst_ip: "10.0.0.5", first_ts: 1, evidence: { events: 8, window_seconds: 3.5 } }] },
};
const WAIT = { timeout: 3000 };

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.rules.mockResolvedValue({ items: [{ id: "port_scan", name: "Escaneo", severity: "high", detector: "port_scan", custom: false }], example: EXAMPLE });
  api.previewRule.mockResolvedValue(PREVIEW);
  api.saveRule.mockResolvedValue({ id: "mi_regla", file: "mi_regla.yaml", yaml: PREVIEW.yaml });
});

const renderIt = () => render(<RulesPanel onError={onError} refreshKey={0} />);
const name = () => screen.getByLabelText("Nombre");

describe("toBody", () => {
  it("convierte los números y rechaza los vacíos", () => {
    expect(toBody({ name: "x", port: "22", min_events: "5", window_seconds: "1.5" })).toMatchObject({ port: 22, min_events: 5, window_seconds: 1.5 });
    expect(toBody({ name: "x", port: "", min_events: "5", window_seconds: "1" })).toBeNull();
    expect(toBody({ name: "x", port: "abc", min_events: "5", window_seconds: "1" })).toBeNull();
  });
});

describe("RulesPanel", () => {
  it("sin nombre no consulta la vista previa ni deja guardar", async () => {
    renderIt();
    expect(await screen.findByText(/Completá el nombre/, { selector: "p" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Guardar regla" })).toBeDisabled();
    expect(api.previewRule).not.toHaveBeenCalled();
  });

  it("el botón de ejemplo carga el caso en el formulario y muestra el YAML en vivo", async () => {
    renderIt();
    await screen.findByRole("button", { name: "Cargar un ejemplo" });
    await userEvent.click(screen.getByRole("button", { name: "Cargar un ejemplo" }));
    expect(name()).toHaveValue(EXAMPLE.name);
    expect(screen.getByLabelText("IP o red de destino")).toHaveValue("10.0.0.0/8");
    expect(screen.getByLabelText(/Puerto de destino/)).toHaveValue(22);
    await waitFor(() => expect(screen.getByLabelText("YAML de la regla")).toHaveTextContent("id: mi_regla"), WAIT);
    expect(api.previewRule).toHaveBeenLastCalledWith(expect.objectContaining({ protocol: "tcp", port: 22, min_events: 8, window_seconds: 30 }), expect.any(AbortSignal));
  });

  it("muestra cuántas sesiones y alertas coincidirían, sin guardar", async () => {
    renderIt();
    await userEvent.type(name(), "Mi regla");
    const box = await screen.findByText(/coincidirían con esta captura/, {}, WAIT);
    expect(box.closest("div")).toHaveTextContent("2 alerta(s) y 12 sesión(es)");
    expect(screen.getByText(/1\.1\.1\.1 → 10\.0\.0\.5: 8 eventos en 3\.5 s/)).toBeInTheDocument();
    expect(api.saveRule).not.toHaveBeenCalled();
  });

  it("sin captura abierta lo dice y igual muestra el YAML", async () => {
    api.previewRule.mockResolvedValue({ ...PREVIEW, matches: null });
    renderIt();
    await userEvent.type(name(), "Mi regla");
    expect(await screen.findByText(/Abrí una captura para ver/, {}, WAIT)).toBeInTheDocument();
    expect(screen.getByLabelText("YAML de la regla")).toHaveTextContent("name: Mi regla");
  });

  it("espera a que termines de escribir: una sola consulta para varias teclas", async () => {
    renderIt();
    await userEvent.type(name(), "Mi regla");
    await waitFor(() => expect(api.previewRule).toHaveBeenCalled(), WAIT);
    expect(api.previewRule).toHaveBeenCalledTimes(1);
  });

  it("un error de validación del servidor se muestra y bloquea el guardado", async () => {
    api.previewRule.mockRejectedValue(new Error("param 'src_ip': no es una IP ni una red CIDR"));
    renderIt();
    await userEvent.type(name(), "Mi regla");
    expect(await screen.findByRole("alert", {}, WAIT)).toHaveTextContent("no es una IP ni una red CIDR");
    expect(screen.getByRole("button", { name: "Guardar regla" })).toBeDisabled();
  });

  it("guardar manda el formulario, avisa el archivo creado y recarga la lista", async () => {
    renderIt();
    await userEvent.type(name(), "Mi regla");
    await screen.findByText(/coincidirían/, {}, WAIT);
    await userEvent.click(screen.getByRole("button", { name: "Guardar regla" }));
    expect(api.saveRule).toHaveBeenCalledWith(expect.objectContaining({ name: "Mi regla", min_events: 20 }));
    expect(await screen.findByText(/rules\/mi_regla\.yaml/)).toBeInTheDocument();
    expect(api.rules).toHaveBeenCalledTimes(2);
  });

  it("si ya existe una regla con ese id lo avisa", async () => {
    api.previewRule.mockResolvedValue({ ...PREVIEW, exists: true });
    renderIt();
    await userEvent.type(name(), "Escaneo");
    expect(await screen.findByText(/Ya existe una regla con ese id/, {}, WAIT)).toBeInTheDocument();
  });

  it("si guardar falla (409) muestra el motivo", async () => {
    api.saveRule.mockRejectedValue(new Error("ya existe el archivo mi_regla.yaml"));
    renderIt();
    await userEvent.type(name(), "Mi regla");
    await screen.findByText(/coincidirían/, {}, WAIT);
    await userEvent.click(screen.getByRole("button", { name: "Guardar regla" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("ya existe el archivo");
  });

  it("lista las reglas creadas desde el panel", async () => {
    api.rules.mockResolvedValue({ items: [{ id: "mia", name: "La mía", severity: "low", detector: "threshold", custom: true }], example: EXAMPLE });
    renderIt();
    expect(await screen.findByText(/La mía/)).toBeInTheDocument();
  });

  it("un error al cargar las reglas va a onError", async () => {
    api.rules.mockRejectedValue(new Error("fallo"));
    renderIt();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("fallo"));
  });

  it("el YAML y la evidencia hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.previewRule.mockResolvedValue({ ...PREVIEW, yaml: `name: ${evil}\n`, matches: { sessions: 1, alerts: 1, sample: [{ src_ip: evil, dst_ip: evil, first_ts: 1, evidence: { events: 1, window_seconds: 1 } }] } });
    const { container } = renderIt();
    await userEvent.type(name(), "x");
    await screen.findByText(/coincidirían/, {}, WAIT);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByLabelText("YAML de la regla")).toHaveTextContent(evil);
  });
});
