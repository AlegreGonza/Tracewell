import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Toolbar from "./Toolbar.jsx";

const setup = (props = {}) => {
  const onDemo = vi.fn();
  const onAnalyze = vi.fn();
  render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={onDemo} onAnalyze={onAnalyze} {...props} />);
  return { onDemo, onAnalyze };
};

afterEach(() => {
  delete window.pywebview;
  vi.restoreAllMocks();
});

describe("Toolbar", () => {
  it("Analizar deshabilitado con ruta vacía o solo espacios", async () => {
    setup();
    const btn = screen.getByRole("button", { name: "Analizar" });
    expect(btn).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Ruta del archivo/), "   ");
    expect(btn).toBeDisabled();
  });

  it("envía la ruta recortada (botón y Enter)", async () => {
    const { onAnalyze } = setup();
    const input = screen.getByLabelText(/Ruta del archivo/);
    await userEvent.type(input, "  C:\\caps\\a.pcap  ");
    await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
    expect(onAnalyze).toHaveBeenLastCalledWith("C:\\caps\\a.pcap");
    await userEvent.type(input, "{Enter}");
    expect(onAnalyze).toHaveBeenCalledTimes(2);
  });

  it("Modo demo llama onDemo", async () => {
    const { onDemo } = setup();
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    expect(onDemo).toHaveBeenCalledTimes(1);
  });

  it("busy deshabilita input, demo y analizar", () => {
    setup({ busy: true });
    expect(screen.getByLabelText(/Ruta del archivo/)).toBeDisabled();
    expect(screen.getByRole("button", { name: "Modo demo" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Analizar" })).toBeDisabled();
  });

  it("exportación: deshabilitada (sin link) sin captura", () => {
    setup({ loaded: false });
    expect(screen.queryByRole("link", { name: "Exportar JSON" })).toBeNull();
    expect(screen.getByText("Exportar JSON")).toHaveAttribute("aria-disabled", "true");
  });

  it("exportación: link con filtros en la URL y atributo download", () => {
    setup({ loaded: true, filters: { protocol: "TCP", ip: "10.0.0.1" } });
    const a = screen.getByRole("link", { name: "Exportar JSON" });
    expect(a).toHaveAttribute("href", "/api/export?protocol=TCP&ip=10.0.0.1");
    expect(a).toHaveAttribute("download");
  });

  it("exportación sin filtros", () => {
    setup({ loaded: true, filters: {} });
    expect(screen.getByRole("link", { name: "Exportar JSON" })).toHaveAttribute("href", "/api/export");
  });

  it("sin pywebview no hay botón Examinar", () => {
    setup();
    expect(screen.queryByRole("button", { name: /Examinar/ })).toBeNull();
  });

  it("con pick_file, Examinar usa su resultado y analiza", async () => {
    window.pywebview = { api: { pick_file: vi.fn().mockResolvedValue("D:\\x.pcapng") } };
    const { onAnalyze } = setup();
    await userEvent.click(screen.getByRole("button", { name: /Examinar/ }));
    expect(onAnalyze).toHaveBeenCalledWith("D:\\x.pcapng");
    expect(screen.getByLabelText(/Ruta del archivo/)).toHaveValue("D:\\x.pcapng");
  });

  it("Examinar cancelado (null) no analiza", async () => {
    window.pywebview = { api: { pick_file: vi.fn().mockResolvedValue(null) } };
    const { onAnalyze } = setup();
    await userEvent.click(screen.getByRole("button", { name: /Examinar/ }));
    expect(onAnalyze).not.toHaveBeenCalled();
  });
  describe("pywebviewready", () => {
    const ready = () => act(() => { window.dispatchEvent(new Event("pywebviewready")); });
    const examinar = () => screen.queryByRole("button", { name: "Examinar…" });
    const renderBare = () => {
      const onAnalyze = vi.fn();
      const view = render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={vi.fn()} onAnalyze={onAnalyze} />);
      return { onAnalyze, ...view };
    };

    it("pywebview inyectado después del montaje: aparece Examinar, pick_file se llama una vez y analiza", async () => {
      const { onAnalyze } = renderBare();
      expect(examinar()).toBeNull();
      const pick_file = vi.fn().mockResolvedValue("E:\\y.pcap");
      window.pywebview = { api: { pick_file } };
      ready();
      expect(examinar()).toBeInTheDocument();
      expect(pick_file).not.toHaveBeenCalled();
      await userEvent.click(examinar());
      expect(pick_file).toHaveBeenCalledTimes(1);
      expect(screen.getByLabelText(/Ruta del archivo/)).toHaveValue("E:\\y.pcap");
      expect(onAnalyze).toHaveBeenCalledTimes(1);
      expect(onAnalyze).toHaveBeenCalledWith("E:\\y.pcap");
    });

    it("pick_file cancelado (null) no cambia el campo ni analiza", async () => {
      const pick_file = vi.fn().mockResolvedValue(null);
      const { onAnalyze } = renderBare();
      window.pywebview = { api: { pick_file } };
      ready();
      const input = screen.getByLabelText(/Ruta del archivo/);
      await userEvent.type(input, "previa.pcap");
      await userEvent.click(examinar());
      expect(pick_file).toHaveBeenCalledTimes(1);
      expect(input).toHaveValue("previa.pcap");
      expect(onAnalyze).not.toHaveBeenCalled();
    });

    it("evento sin window.pywebview.api todavía: no rompe y no hay botón", () => {
      renderBare();
      expect(() => ready()).not.toThrow();
      expect(examinar()).toBeNull();
      window.pywebview = {}; // pywebview sin api aún
      expect(() => ready()).not.toThrow();
      expect(examinar()).toBeNull();
    });

    it("tras desmontar, el evento no genera errores ni warnings de React", () => {
      const err = vi.spyOn(console, "error").mockImplementation(() => {});
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const { unmount } = renderBare();
      unmount();
      window.pywebview = { api: { pick_file: vi.fn() } };
      expect(() => ready()).not.toThrow();
      expect(err).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
    });

    it("el listener se registra una vez y se quita al desmontar", () => {
      const add = vi.spyOn(window, "addEventListener");
      const remove = vi.spyOn(window, "removeEventListener");
      const count = (spy) => spy.mock.calls.filter((c) => c[0] === "pywebviewready");
      const { unmount } = renderBare();
      expect(count(add)).toHaveLength(1);
      expect(count(remove)).toHaveLength(0);
      unmount();
      expect(count(add)).toHaveLength(1);
      expect(count(remove)).toHaveLength(1);
      expect(count(remove)[0][1]).toBe(count(add)[0][1]); // misma función
    });

    // Captura los unhandledRejection de Node durante `fn` (vitest falla la corrida si hay alguno).
    const trackUnhandled = async (fn) => {
      const saved = process.listeners("unhandledRejection");
      process.removeAllListeners("unhandledRejection");
      const seen = [];
      const h = (e) => seen.push(e);
      process.on("unhandledRejection", h);
      try {
        await fn();
        await new Promise((r) => setTimeout(r, 20));
      } finally {
        process.off("unhandledRejection", h);
        saved.forEach((l) => process.on("unhandledRejection", l));
      }
      return seen;
    };
    const rejecting = (reason) => {
      window.pywebview = { api: { pick_file: vi.fn().mockRejectedValue(reason) } };
    };

    it("pick_file que rechaza: llama onError con el message, no analiza ni cambia el campo, sin rechazo sin manejar", async () => {
      rejecting(new Error("dialogo roto"));
      const onError = vi.fn();
      const onAnalyze = vi.fn();
      render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={vi.fn()} onAnalyze={onAnalyze} onError={onError} />);
      const input = screen.getByLabelText(/Ruta del archivo/);
      await userEvent.type(input, "previa.pcap");
      const seen = await trackUnhandled(() => userEvent.click(examinar()));
      expect(seen).toEqual([]);
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith("dialogo roto");
      expect(onAnalyze).not.toHaveBeenCalled();
      expect(input).toHaveValue("previa.pcap");
    });

    it("error sin message usa el texto por defecto", async () => {
      rejecting(new Error(""));
      const onError = vi.fn();
      render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={vi.fn()} onAnalyze={vi.fn()} onError={onError} />);
      await userEvent.click(examinar());
      expect(onError).toHaveBeenCalledWith("No se pudo abrir el selector de archivos.");
    });

    it.each([[null], [undefined], ["texto suelto"], [{}], [{ code: 5 }]])(
      "rechazo con %j (sin message): usa el texto por defecto y no rompe",
      async (reason) => {
        rejecting(reason);
        const onError = vi.fn();
        render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={vi.fn()} onAnalyze={vi.fn()} onError={onError} />);
        const seen = await trackUnhandled(() => userEvent.click(examinar()));
        expect(seen).toEqual([]);
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith("No se pudo abrir el selector de archivos.");
      },
    );

    it("sin prop onError: no lanza ni genera unhandledrejection y no analiza", async () => {
      rejecting(new Error("dialogo roto"));
      const { onAnalyze } = renderBare();
      const seen = await trackUnhandled(() => userEvent.click(examinar()));
      expect(seen).toEqual([]);
      expect(onAnalyze).not.toHaveBeenCalled();
      expect(examinar()).toBeInTheDocument();
    });
  });

  it("el botón de cerrar solo aparece con captura cargada y onClose", () => {
    setup({ loaded: false, onClose: vi.fn() });
    expect(screen.queryByRole("button", { name: "Cerrar captura" })).toBeNull();
  });

  it("sin onClose no hay botón aunque haya captura", () => {
    setup({ loaded: true });
    expect(screen.queryByRole("button", { name: "Cerrar captura" })).toBeNull();
  });

  it("con loaded y onClose: etiqueta por defecto 'Cerrar captura' y un clic llama onClose", async () => {
    const onClose = vi.fn();
    setup({ loaded: true, onClose });
    await userEvent.click(screen.getByRole("button", { name: "Cerrar captura" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closeLabel personalizado", () => {
    setup({ loaded: true, onClose: vi.fn(), closeLabel: "Salir del demo" });
    expect(screen.getByRole("button", { name: "Salir del demo" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cerrar captura" })).toBeNull();
  });

  it("deshabilitado mientras busy y no llama onClose", async () => {
    const onClose = vi.fn();
    setup({ loaded: true, busy: true, onClose });
    const b = screen.getByRole("button", { name: "Cerrar captura" });
    expect(b).toBeDisabled();
    await userEvent.click(b);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("sin onGlossary no hay botón Glosario", () => {
    setup();
    expect(screen.queryByRole("button", { name: "Glosario" })).toBeNull();
  });

  it("con onGlossary el botón aparece (también sin captura) y un clic lo llama", async () => {
    const onGlossary = vi.fn();
    setup({ loaded: false, onGlossary });
    await userEvent.click(screen.getByRole("button", { name: "Glosario" }));
    expect(onGlossary).toHaveBeenCalledTimes(1);
  });

  it("el botón Glosario sigue activo aunque la app esté ocupada", () => {
    setup({ busy: true, onGlossary: vi.fn() });
    expect(screen.getByRole("button", { name: "Glosario" })).toBeEnabled();
  });
});
