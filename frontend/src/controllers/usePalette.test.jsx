import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { usePalette } from "./usePalette.js";

const KEY = "tracewell-palette";
beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-palette");
});
afterEach(() => vi.restoreAllMocks());

describe("usePalette", () => {
  it("por defecto es esmeralda y la aplica en <html>", () => {
    const { result } = renderHook(() => usePalette());
    expect(result.current[0]).toBe("esmeralda");
    expect(document.documentElement).toHaveAttribute("data-palette", "esmeralda");
  });

  it("lee la paleta guardada", () => {
    window.localStorage.setItem(KEY, "violeta");
    const { result } = renderHook(() => usePalette());
    expect(result.current[0]).toBe("violeta");
    expect(document.documentElement).toHaveAttribute("data-palette", "violeta");
  });

  it("un valor guardado inválido se ignora", () => {
    window.localStorage.setItem(KEY, "<script>");
    expect(renderHook(() => usePalette()).result.current[0]).toBe("esmeralda");
  });

  it("setPalette cambia, guarda y actualiza data-palette", () => {
    const { result } = renderHook(() => usePalette());
    act(() => result.current[1]("terracota"));
    expect(result.current[0]).toBe("terracota");
    expect(window.localStorage.getItem(KEY)).toBe("terracota");
    expect(document.documentElement).toHaveAttribute("data-palette", "terracota");
  });

  it("setPalette ignora valores inválidos", () => {
    const { result } = renderHook(() => usePalette());
    act(() => result.current[1]("violeta"));
    act(() => result.current[1]("rojo"));
    act(() => result.current[1](undefined));
    expect(result.current[0]).toBe("violeta");
    expect(window.localStorage.getItem(KEY)).toBe("violeta");
  });

  it("si el almacenamiento falla al leer, usa esmeralda", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("bloqueado");
    });
    expect(renderHook(() => usePalette()).result.current[0]).toBe("esmeralda");
  });

  it("si el almacenamiento falla al guardar, la elección vale igual en la sesión", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("lleno");
    });
    const { result } = renderHook(() => usePalette());
    expect(() => act(() => result.current[1]("violeta"))).not.toThrow();
    expect(result.current[0]).toBe("violeta");
    expect(document.documentElement).toHaveAttribute("data-palette", "violeta");
  });
});
