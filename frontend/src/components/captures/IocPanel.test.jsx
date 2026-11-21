import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn() } }));
import { api } from "../../api/client.js";
import IocPanel from "./IocPanel.jsx";

const EMPTY = { loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 };
const LOADED = { loaded: true, source: "feed.txt", ips: 3, networks: 2, domains: 1, sessions: 4 };

let onChange, onError;
beforeEach(() => {
  vi.clearAllMocks();
  onChange = vi.fn();
  onError = vi.fn();
  api.iocs.mockResolvedValue(EMPTY);
});

const renderIt = () => render(<IocPanel onChange={onChange} onError={onError} />);
const input = () => screen.getByLabelText("Ruta del archivo de indicadores");

describe("IocPanel", () => {
  it("al montar consulta api.iocs y sin lista muestra 'Sin lista cargada' y no ofrece Quitar", async () => {
    renderIt();
    expect(await screen.findByRole("status")).toHaveTextContent("Sin lista cargada");
    expect(api.iocs).toHaveBeenCalledTimes(1);
    expect(api.iocs).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(screen.queryByRole("button", { name: "Quitar" })).toBeNull();
  });

  it("con una lista cargada muestra el resumen y Quitar", async () => {
    api.iocs.mockResolvedValue(LOADED);
    renderIt();
    expect(await screen.findByRole("status")).toHaveTextContent(
      "feed.txt: 3 IP · 2 redes · 1 dominios · 4 sesiones coinciden",
    );
    expect(screen.getByRole("button", { name: "Quitar" })).toBeEnabled();
  });

  it("'Cargar lista' está deshabilitado con la ruta vacía o solo espacios", async () => {
    renderIt();
    await screen.findByText("Sin lista cargada");
    const btn = screen.getByRole("button", { name: "Cargar lista" });
    expect(btn).toBeDisabled();
    await userEvent.type(input(), "   ");
    expect(btn).toBeDisabled();
    await userEvent.type(input(), "a.txt");
    expect(btn).toBeEnabled();
  });

  it("carga con la ruta recortada, actualiza el estado y avisa con onChange", async () => {
    api.loadIocs.mockResolvedValue(LOADED);
    renderIt();
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "  C:\\listas\\feed.txt  ");
    await userEvent.click(screen.getByRole("button", { name: "Cargar lista" }));
    expect(api.loadIocs).toHaveBeenCalledWith("C:\\listas\\feed.txt");
    expect(await screen.findByText(/feed\.txt: 3 IP/)).toBeInTheDocument();
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onError).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Quitar" })).toBeInTheDocument();
  });

  it("Enter en el campo también carga", async () => {
    api.loadIocs.mockResolvedValue(LOADED);
    renderIt();
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "x.txt{Enter}");
    expect(api.loadIocs).toHaveBeenCalledWith("x.txt");
  });

  it("Enter con la ruta vacía no llama a la API", async () => {
    renderIt();
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "   {Enter}");
    expect(api.loadIocs).not.toHaveBeenCalled();
  });

  it("error al cargar (422) va a onError, no cambia el estado y no llama onChange", async () => {
    api.loadIocs.mockRejectedValue(Object.assign(new Error("línea 2: no es una IP"), { status: 422 }));
    renderIt();
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "mala.txt");
    await userEvent.click(screen.getByRole("button", { name: "Cargar lista" }));
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("línea 2: no es una IP"));
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent("Sin lista cargada");
    expect(input()).toBeEnabled(); // busy se libera
    expect(input()).toHaveValue("mala.txt");
  });

  it("error de red al montar va a onError", async () => {
    api.iocs.mockRejectedValue(Object.assign(new Error("sin API"), { status: 0 }));
    renderIt();
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("sin API"));
    expect(screen.getByRole("status")).toHaveTextContent("Sin lista cargada");
  });

  it("un AbortError al desmontar no se reporta", async () => {
    let reject;
    api.iocs.mockReturnValue(new Promise((_, r) => { reject = r; }));
    const { unmount } = renderIt();
    unmount();
    reject(Object.assign(new Error("abortado"), { name: "AbortError" }));
    await Promise.resolve();
    expect(onError).not.toHaveBeenCalled();
  });

  it("Quitar llama api.clearIocs, vuelve a 'Sin lista cargada' y avisa con onChange", async () => {
    api.iocs.mockResolvedValue(LOADED);
    api.clearIocs.mockResolvedValue(EMPTY);
    renderIt();
    await userEvent.click(await screen.findByRole("button", { name: "Quitar" }));
    expect(api.clearIocs).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Sin lista cargada")).toBeInTheDocument();
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Quitar" })).toBeNull();
  });

  it("error al quitar va a onError y conserva la lista", async () => {
    api.iocs.mockResolvedValue(LOADED);
    api.clearIocs.mockRejectedValue(new Error("falló"));
    renderIt();
    await userEvent.click(await screen.findByRole("button", { name: "Quitar" }));
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("falló"));
    expect(screen.getByRole("status")).toHaveTextContent("feed.txt");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("mientras carga, el campo y los botones se deshabilitan (evita doble envío)", async () => {
    let resolve;
    api.loadIocs.mockReturnValue(new Promise((r) => { resolve = r; }));
    renderIt();
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "x.txt");
    await userEvent.click(screen.getByRole("button", { name: "Cargar lista" }));
    expect(input()).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cargar lista" })).toBeDisabled();
    resolve(LOADED);
    await screen.findByText(/feed\.txt/);
    expect(input()).toBeEnabled();
    expect(api.loadIocs).toHaveBeenCalledTimes(1);
  });

  it("el nombre de la lista se muestra como texto aunque tenga marcado HTML", async () => {
    api.iocs.mockResolvedValue({ ...LOADED, source: "<img src=x onerror=alert(1)>.txt" });
    const { container } = renderIt();
    expect(await screen.findByRole("status")).toHaveTextContent("<img src=x onerror=alert(1)>.txt");
    expect(container.querySelector("img")).toBeNull();
  });

  it("funciona sin onChange (prop opcional)", async () => {
    api.loadIocs.mockResolvedValue(LOADED);
    render(<IocPanel onError={onError} />);
    await screen.findByText("Sin lista cargada");
    await userEvent.type(input(), "x.txt{Enter}");
    expect(await screen.findByText(/feed\.txt/)).toBeInTheDocument();
  });
});
