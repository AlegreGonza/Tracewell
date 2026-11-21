import { describe, it, expect, vi } from "vitest";
import { render, screen, renderHook, act, waitFor } from "@testing-library/react";
import { useAction } from "./useAction.js";
import { useLoad } from "./useLoad.js";
import RefreshButton from "../components/support/RefreshButton.jsx";

const abortErr = () => Object.assign(new Error("abort"), { name: "AbortError" });
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => ((resolve = a), (reject = b)));
  return { promise, resolve, reject };
};

describe("useAction", () => {
  it("no hace nada hasta run(); run guarda el resultado y pasa los argumentos + signal", async () => {
    const fn = vi.fn().mockResolvedValue({ ok: 1 });
    const { result } = renderHook(() => useAction(fn));
    expect(fn).not.toHaveBeenCalled();
    expect(result.current).toMatchObject({ loading: false, result: null, error: null });
    let ret;
    await act(async () => {
      ret = await result.current.run("a", 2);
    });
    expect(ret).toEqual({ ok: 1 });
    expect(fn.mock.calls[0].slice(0, 2)).toEqual(["a", 2]);
    expect(fn.mock.calls[0][2]).toBeInstanceOf(AbortSignal);
    expect(result.current).toMatchObject({ loading: false, result: { ok: 1 }, error: null });
  });

  it("loading mientras trabaja", async () => {
    const d = deferred();
    const { result } = renderHook(() => useAction(() => d.promise));
    act(() => void result.current.run());
    expect(result.current.loading).toBe(true);
    await act(async () => d.resolve(5));
    expect(result.current.loading).toBe(false);
  });

  it("un error queda como mensaje y devuelve null", async () => {
    const { result } = renderHook(() => useAction(() => Promise.reject(new Error("boom"))));
    let ret;
    await act(async () => {
      ret = await result.current.run();
    });
    expect(ret).toBeNull();
    expect(result.current).toMatchObject({ loading: false, error: "boom" });
  });

  it("un AbortError se ignora", async () => {
    const { result } = renderHook(() => useAction(() => Promise.reject(abortErr())));
    await act(async () => {
      await result.current.run();
    });
    expect(result.current.error).toBeNull();
  });

  it("descarta la ejecución vieja si llega otra después", async () => {
    const first = deferred();
    const second = deferred();
    const fn = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => useAction(fn));
    let p1, p2;
    act(() => {
      p1 = result.current.run("uno");
      p2 = result.current.run("dos");
    });
    expect(fn.mock.calls[0][1].aborted).toBe(true); // la primera señal quedó abortada
    await act(async () => {
      second.resolve("segunda");
      await p2;
    });
    await act(async () => {
      first.resolve("primera (vieja)");
      await p1;
    });
    expect(result.current.result).toBe("segunda");
  });

  it("un error de la ejecución vieja no pisa a la nueva", async () => {
    const first = deferred();
    const fn = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValueOnce("nueva");
    const { result } = renderHook(() => useAction(fn));
    let p1;
    act(() => void (p1 = result.current.run()));
    await act(async () => {
      await result.current.run();
    });
    await act(async () => {
      first.reject(new Error("vieja falló"));
      await p1;
    });
    expect(result.current).toMatchObject({ result: "nueva", error: null });
  });

  it("reset vuelve al estado inicial y aborta lo pendiente", async () => {
    const d = deferred();
    const fn = vi.fn().mockReturnValue(d.promise);
    const { result } = renderHook(() => useAction(fn));
    act(() => void result.current.run());
    act(() => result.current.reset());
    expect(fn.mock.calls[0][0].aborted).toBe(true);
    expect(result.current).toMatchObject({ loading: false, result: null, error: null });
  });

  it("al desmontar aborta lo pendiente", () => {
    const fn = vi.fn().mockReturnValue(new Promise(() => {}));
    const { result, unmount } = renderHook(() => useAction(fn));
    act(() => void result.current.run());
    unmount();
    expect(fn.mock.calls[0][0].aborted).toBe(true);
  });
});

describe("RefreshButton y useLoad.updatedAt", () => {
  it("sin hora ni carga no muestra estado; llama a onClick", () => {
    const onClick = vi.fn();
    render(<RefreshButton onClick={onClick} loading={false} updatedAt={null} />);
    expect(screen.getByRole("status")).toHaveTextContent("");
    screen.getByRole("button", { name: "Actualizar" }).click();
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("«Actualizando…» y el botón deshabilitado mientras carga", () => {
    render(<RefreshButton onClick={() => {}} loading updatedAt={new Date()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Actualizando…");
    expect(screen.getByRole("button", { name: "Actualizar" })).toBeDisabled();
  });

  it("«Actualizado hh:mm:ss» con la hora", () => {
    const d = new Date(2026, 0, 2, 3, 4, 5);
    render(<RefreshButton onClick={() => {}} loading={false} updatedAt={d} />);
    expect(screen.getByRole("status")).toHaveTextContent(`Actualizado ${d.toLocaleTimeString("es-AR")}`);
  });

  it("link usa la clase link", () => {
    render(<RefreshButton link onClick={() => {}} loading={false} updatedAt={null} />);
    expect(screen.getByRole("button")).toHaveClass("link");
  });

  it("useLoad.updatedAt: null al principio, una fecha cuando llegan los datos, y se renueva en reload", async () => {
    const fetcher = vi.fn().mockResolvedValue({});
    const { result } = renderHook(() => useLoad(fetcher));
    expect(result.current.updatedAt).toBeNull();
    await waitFor(() => expect(result.current.updatedAt).toBeInstanceOf(Date));
    const first = result.current.updatedAt;
    await new Promise((r) => setTimeout(r, 5));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.updatedAt.getTime()).toBeGreaterThan(first.getTime()));
  });

  it("useLoad.updatedAt no se pone si falla", async () => {
    const { result } = renderHook(() => useLoad(() => Promise.reject(new Error("x"))));
    await waitFor(() => expect(result.current.error).toBe("x"));
    expect(result.current.updatedAt).toBeNull();
  });
});
