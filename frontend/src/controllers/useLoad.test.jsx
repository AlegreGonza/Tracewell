import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useLoad } from "./useLoad.js";

const abortErr = () => Object.assign(new Error("abort"), { name: "AbortError" });

let fetcher;
beforeEach(() => {
  fetcher = vi.fn().mockResolvedValue({ n: 1 });
});
afterEach(() => vi.useRealTimers());

describe("useLoad", () => {
  it("carga al montar: loading al principio y datos después", async () => {
    const { result } = renderHook(() => useLoad(fetcher));
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBeNull();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ n: 1 });
    expect(result.current.error).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
  });

  it("un error se guarda como mensaje y deja de cargar", async () => {
    fetcher.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
  });

  it("un AbortError se ignora (no es un error de verdad)", async () => {
    fetcher.mockRejectedValue(abortErr());
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(fetcher).toHaveBeenCalled());
    await act(async () => {});
    expect(result.current.error).toBeNull();
  });

  it("reload() vuelve a pedir, aborta el pedido anterior y se queda con lo nuevo", async () => {
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(result.current.data).toEqual({ n: 1 }));
    fetcher.mockResolvedValue({ n: 2 });
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.data).toEqual({ n: 2 }));
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][0].aborted).toBe(true);
    expect(fetcher.mock.calls[1][0].aborted).toBe(false);
  });

  it("al recargar conserva los datos viejos (sin parpadeo) y marca loading", async () => {
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(result.current.data).toEqual({ n: 1 }));
    let resolve;
    fetcher.mockReturnValue(new Promise((r) => (resolve = r)));
    act(() => result.current.reload());
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toEqual({ n: 1 });
    await act(async () => resolve({ n: 9 }));
    expect(result.current.data).toEqual({ n: 9 });
    expect(result.current.loading).toBe(false);
  });

  it("un éxito después de un error borra el error", async () => {
    fetcher.mockRejectedValueOnce(new Error("mal"));
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(result.current.error).toBe("mal"));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.error).toBeNull());
    expect(result.current.data).toEqual({ n: 1 });
  });

  it("un error tras haber tenido datos conserva los datos", async () => {
    const { result } = renderHook(() => useLoad(fetcher));
    await waitFor(() => expect(result.current.data).toEqual({ n: 1 }));
    fetcher.mockRejectedValue(new Error("cayó"));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.error).toBe("cayó"));
    expect(result.current.data).toEqual({ n: 1 });
  });

  it("cuando cambian las deps vuelve a pedir", async () => {
    const { result, rerender } = renderHook(({ s }) => useLoad(fetcher, { deps: [s] }), { initialProps: { s: "ram" } });
    await waitFor(() => expect(result.current.data).not.toBeNull());
    rerender({ s: "cpu" });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(fetcher.mock.calls[0][0].aborted).toBe(true);
    rerender({ s: "cpu" });
    expect(fetcher).toHaveBeenCalledTimes(2); // mismas deps: no repite
  });

  it("usa siempre la versión más nueva del fetcher (sin volver a pedir al cambiarla)", async () => {
    const f1 = vi.fn().mockResolvedValue("uno");
    const f2 = vi.fn().mockResolvedValue("dos");
    const { result, rerender } = renderHook(({ f }) => useLoad(f), { initialProps: { f: f1 } });
    await waitFor(() => expect(result.current.data).toBe("uno"));
    rerender({ f: f2 });
    expect(f2).not.toHaveBeenCalled();
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.data).toBe("dos"));
  });

  it("al desmontar aborta el pedido en curso", async () => {
    fetcher.mockReturnValue(new Promise(() => {}));
    const { unmount } = renderHook(() => useLoad(fetcher));
    const signal = fetcher.mock.calls[0][0];
    expect(signal.aborted).toBe(false);
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("reload devuelve siempre la misma función (estable)", async () => {
    const { result, rerender } = renderHook(() => useLoad(fetcher));
    const first = result.current.reload;
    rerender();
    expect(result.current.reload).toBe(first);
  });

  describe("auto-refresco", () => {
    it("con every y active recarga sola cada tanto", async () => {
      vi.useFakeTimers();
      renderHook(() => useLoad(fetcher, { every: 5000, active: true }));
      await act(async () => {});
      expect(fetcher).toHaveBeenCalledTimes(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(4999); });
      expect(fetcher).toHaveBeenCalledTimes(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(1); });
      expect(fetcher).toHaveBeenCalledTimes(2);
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
      expect(fetcher).toHaveBeenCalledTimes(4);
    });

    it("sin every (0) no recarga sola", async () => {
      vi.useFakeTimers();
      renderHook(() => useLoad(fetcher, { every: 0, active: true }));
      await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
      expect(fetcher).toHaveBeenCalledTimes(1);
    });

    it("con active en false no recarga sola, y vuelve a hacerlo al activarse", async () => {
      vi.useFakeTimers();
      const { rerender } = renderHook(({ active }) => useLoad(fetcher, { every: 1000, active }), { initialProps: { active: false } });
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(fetcher).toHaveBeenCalledTimes(1);
      rerender({ active: true });
      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(fetcher).toHaveBeenCalledTimes(3);
      rerender({ active: false });
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(fetcher).toHaveBeenCalledTimes(3);
    });

    it("cambiar every cambia el ritmo, sin pedir de más al cambiarlo", async () => {
      vi.useFakeTimers();
      const { rerender } = renderHook(({ every }) => useLoad(fetcher, { every, active: true }), { initialProps: { every: 0 } });
      await act(async () => {});
      rerender({ every: 2000 });
      expect(fetcher).toHaveBeenCalledTimes(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(fetcher).toHaveBeenCalledTimes(2);
    });

    it("al desmontar se corta el temporizador", async () => {
      vi.useFakeTimers();
      const { unmount } = renderHook(() => useLoad(fetcher, { every: 1000, active: true }));
      await act(async () => {});
      unmount();
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
      expect(fetcher).toHaveBeenCalledTimes(1);
    });
  });
});
