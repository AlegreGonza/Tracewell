import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { stream: vi.fn() } }));
import { api } from "../../api/client.js";
import StreamView from "./StreamView.jsx";

const tcp = { id: 3, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1, dst_ip: "10.0.0.2", dst_port: 21 };
const ok = (over = {}) => ({
  chunks: [
    { from: "destino", bytes: 15, text: "220 FTP ready\r\n" },
    { from: "origen", bytes: 12, text: "USER admin\r\n" },
  ],
  origin_bytes: 12, destination_bytes: 15, encrypted: false, truncated: false, ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.stream.mockResolvedValue(ok());
});

const show = (session = tcp) => render(<StreamView session={session} onError={onError} />);
const open = async () => userEvent.click(screen.getByRole("button", { name: "Ver la conversación" }));

describe("StreamView", () => {
  it.each(["UDP", "ICMP", "ICMPv6", "IP-47", "tcp", undefined])("no renderiza nada para el protocolo %s", (protocol) => {
    const { container } = show({ ...tcp, protocol });
    expect(container).toBeEmptyDOMElement();
  });

  it("estado inicial: botón y nada pedido", () => {
    show();
    expect(screen.getByRole("heading", { name: /^Conversación/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ver la conversación" })).toBeInTheDocument();
    expect(api.stream).not.toHaveBeenCalled();
  });

  it("un clic llama a api.stream(id) una vez y muestra 'Reconstruyendo…' y luego el cuerpo", async () => {
    let resolve;
    api.stream.mockReturnValue(new Promise((r) => (resolve = r)));
    show();
    await open();
    expect(screen.getByText("Reconstruyendo…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Ver la conversación" })).toBeNull();
    resolve(ok());
    expect(await screen.findByText("→ Origen · 12 B")).toBeInTheDocument();
    expect(screen.queryByText("Reconstruyendo…")).toBeNull();
    expect(api.stream).toHaveBeenCalledTimes(1);
    expect(api.stream).toHaveBeenCalledWith(3);
  });

  it("etiquetas de turno y el texto en un <pre>", async () => {
    const { container } = show();
    await open();
    expect(await screen.findByText("← Destino · 15 B")).toBeInTheDocument();
    expect(screen.getByText("→ Origen · 12 B")).toBeInTheDocument();
    const pres = Array.from(container.querySelectorAll("pre"));
    expect(pres.map((p) => p.textContent)).toEqual(["220 FTP ready\r\n", "USER admin\r\n"]);
    expect(container.querySelector(".chunk-destino")).not.toBeNull();
    expect(container.querySelector(".chunk-origen")).not.toBeNull();
    expect(container.textContent).toContain("Origen (quien inició): 12 B · Destino: 15 B");
  });

  it("texto hostil se queda como texto", async () => {
    const evil = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    api.stream.mockResolvedValue(ok({ chunks: [{ from: "origen", bytes: evil.length, text: evil }] }));
    const { container } = show();
    await open();
    await screen.findByText(`→ Origen · ${evil.length} B`);
    expect(container.querySelector("pre").textContent).toBe(evil);
    expect(container.querySelector("img, script")).toBeNull();
  });

  it("un bloque 'gap' muestra cuántos bytes faltan", async () => {
    api.stream.mockResolvedValue(
      ok({
        chunks: [
          { from: "origen", bytes: 1, text: "a" }, { gap: 12 }, { gap: 1234567 }, { from: "origen", bytes: 1, text: "b" },
        ],
      }),
    );
    const { container } = show();
    await open();
    expect(await screen.findByText("[faltan 12 bytes: no están en la captura]")).toBeInTheDocument();
    expect(screen.getByText(/\[faltan 1\.234\.567 bytes: no están en la captura\]/)).toBeInTheDocument();
    expect(container.querySelectorAll("pre")).toHaveLength(2);
    expect(container.querySelectorAll(".chunk-gap")).toHaveLength(2);
  });

  it("gap de 0 igualmente no rompe", async () => {
    api.stream.mockResolvedValue(ok({ chunks: [{ gap: 0 }] }));
    show();
    await open();
    expect(await screen.findByText("[faltan 0 bytes: no están en la captura]")).toBeInTheDocument();
  });

  it("cifrado: banner role=note, sin bloques ni <pre>", async () => {
    api.stream.mockResolvedValue(
      ok({ encrypted: true, origin_bytes: 2048, destination_bytes: 100, chunks: [{ from: "origen", bytes: 2048, text: "" }] }),
    );
    const { container } = show();
    await open();
    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent("Sesión cifrada (TLS)");
    expect(note).toHaveTextContent("2.00 KB del origen");
    expect(note).toHaveTextContent("100 B del destino");
    expect(container.querySelector("pre")).toBeNull();
    expect(screen.queryByText(/→ Origen/)).toBeNull();
  });

  it("sin bloques: mensaje de sesión sin datos", async () => {
    api.stream.mockResolvedValue(ok({ chunks: [], origin_bytes: 0, destination_bytes: 0 }));
    const { container } = show();
    await open();
    expect(await screen.findByText(/Esta sesión no tiene datos/)).toBeInTheDocument();
    expect(container.querySelector("pre")).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("truncated: aviso role=note y los bloques igualmente", async () => {
    api.stream.mockResolvedValue(ok({ truncated: true }));
    const { container } = show();
    await open();
    expect(await screen.findByRole("note")).toHaveTextContent("Conversación recortada");
    expect(container.querySelectorAll("pre")).toHaveLength(2);
  });

  it("sin truncated no hay aviso", async () => {
    show();
    await open();
    await screen.findByText("→ Origen · 12 B");
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("un error llama a onError con el mensaje y vuelve al estado inicial (botón visible)", async () => {
    api.stream.mockRejectedValue(new Error("la sesión no existe"));
    show();
    await open();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("la sesión no existe"));
    expect(await screen.findByRole("button", { name: "Ver la conversación" })).toBeInTheDocument();
    expect(screen.queryByText("Reconstruyendo…")).toBeNull();
    api.stream.mockResolvedValue(ok());
    await open();
    expect(await screen.findByText("→ Origen · 12 B")).toBeInTheDocument();
    expect(api.stream).toHaveBeenCalledTimes(2);
  });

  it("al cambiar de sesión vuelve al estado inicial y no pide nada solo", async () => {
    const { rerender } = show();
    await open();
    await screen.findByText("→ Origen · 12 B");
    rerender(<StreamView session={{ ...tcp, id: 4 }} onError={onError} />);
    expect(await screen.findByRole("button", { name: "Ver la conversación" })).toBeInTheDocument();
    expect(screen.queryByText("→ Origen · 12 B")).toBeNull();
    expect(api.stream).toHaveBeenCalledTimes(1);
    await open();
    expect(api.stream).toHaveBeenLastCalledWith(4);
  });

  it("pasar a una sesión UDP oculta todo y volver a TCP arranca en reposo", async () => {
    const { rerender, container } = show();
    await open();
    await screen.findByText("→ Origen · 12 B");
    rerender(<StreamView session={{ ...tcp, id: 5, protocol: "UDP" }} onError={onError} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<StreamView session={{ ...tcp, id: 6 }} onError={onError} />);
    expect(await screen.findByRole("button", { name: "Ver la conversación" })).toBeInTheDocument();
  });

  it("doble clic no pide dos veces (el botón desaparece al cargar)", async () => {
    api.stream.mockReturnValue(new Promise(() => {}));
    show();
    await userEvent.dblClick(screen.getByRole("button", { name: "Ver la conversación" }));
    expect(api.stream).toHaveBeenCalledTimes(1);
  });
});
