import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import CopyFilterButton from "./CopyFilterButton.jsx";

let writeText;
beforeEach(() => {
  writeText = vi.fn().mockResolvedValue();
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
});

describe("CopyFilterButton", () => {
  it("copia el filtro que ya trae y lo muestra", async () => {
    render(<CopyFilterButton filter="ip.addr==10.0.0.5" />);
    await userEvent.click(screen.getByRole("button", { name: "Copiar filtro Wireshark" }));
    expect(writeText).toHaveBeenCalledWith("ip.addr==10.0.0.5");
    expect(screen.getByText("ip.addr==10.0.0.5")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Copiado");
  });

  it("pide el filtro al hacer clic cuando no lo trae", async () => {
    const load = vi.fn().mockResolvedValue("tcp.port==443");
    render(<CopyFilterButton load={load} />);
    expect(load).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button"));
    expect(load).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith("tcp.port==443");
  });

  it("sin portapapeles deja el filtro a la vista y avisa", async () => {
    writeText.mockRejectedValue(new Error("denegado"));
    render(<CopyFilterButton filter="udp.port==53" />);
    await userEvent.click(screen.getByRole("button"));
    expect(screen.getByText("udp.port==53")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("No se pudo copiar solo");
  });

  it("si no hay filtro avisa por onError y no copia", async () => {
    const onError = vi.fn();
    render(<CopyFilterButton load={() => Promise.resolve(undefined)} onError={onError} />);
    await userEvent.click(screen.getByRole("button"));
    expect(onError).toHaveBeenCalledWith("No hay un filtro de Wireshark para esto.");
    expect(writeText).not.toHaveBeenCalled();
  });

  it("si cargar el filtro falla lo informa", async () => {
    const onError = vi.fn();
    render(<CopyFilterButton load={() => Promise.reject(new Error("409"))} onError={onError} />);
    await userEvent.click(screen.getByRole("button"));
    expect(onError).toHaveBeenCalledWith("409");
  });

  it("el filtro se muestra como texto, no como HTML", async () => {
    render(<CopyFilterButton filter={'dns.qry.name=="<img src=x onerror=alert(1)>"'} />);
    await userEvent.click(screen.getByRole("button"));
    expect(document.querySelector("img")).toBeNull();
  });
});
