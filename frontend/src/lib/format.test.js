import { describe, it, expect } from "vitest";
import { formatBytes, formatDuration, formatTime, formatEndpoint, severityLabel, percent } from "./format.js";

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [1023, "1023 B"],
    [1024, "1.00 KB"],
    [1536, "1.50 KB"],
    [10 * 1024, "10.0 KB"],
    [5 * 1024 ** 2, "5.00 MB"],
    [3 * 1024 ** 3, "3.00 GB"],
    [2 * 1024 ** 4, "2.00 TB"],
    [5000 * 1024 ** 4, "5000.0 TB"],
  ])("%s -> %s", (n, out) => expect(formatBytes(n)).toBe(out));
  it("negativo, NaN, Infinity, undefined -> —", () => {
    for (const v of [-1, NaN, Infinity, -Infinity, undefined]) expect(formatBytes(v)).toBe("—");
  });
});

describe("formatBytes redondeo y bordes", () => {
  // Corregido: se compara el valor ya redondeado, así 1023.999 KB sube a "1.00 MB".
  it("1048575 B -> '1.00 MB' (no '1024.0 KB')", () => {
    expect(formatBytes(1048575)).toBe("1.00 MB");
  });
  it.each([
    [1023, "1023 B"],
    [1024, "1.00 KB"],
    [1048576, "1.00 MB"],
    [1073741823, "1.00 GB"],
    [1099511627775, "1.00 TB"],
  ])("borde %s -> %s", (n, out) => expect(formatBytes(n)).toBe(out));
});

describe("formatDuration", () => {
  it.each([
    [0, "0 ms"],
    [0.5, "500 ms"],
    [0.0004, "0 ms"],
    [1, "1.00 s"],
    [12.345, "12.35 s"],
    [60, "1 min 0 s"],
    [125, "2 min 5 s"],
    [3600, "1 h 0 min"],
    [3725, "1 h 2 min"],
  ])("%s -> %s", (n, out) => expect(formatDuration(n)).toBe(out));
  it("negativo y NaN -> —", () => {
    expect(formatDuration(-1)).toBe("—");
    expect(formatDuration(NaN)).toBe("—");
  });
  // Corregido: 0.9996 s redondea a 1000 ms, así que pasa a segundos.
  it("0.9996 s -> '1.00 s' (no '1000 ms')", () => {
    expect(formatDuration(0.9996)).toBe("1.00 s");
  });
  // Corregido: 59.999 s redondea a 60 s, así que pasa a minutos.
  it("59.999 s -> '1 min 0 s' (no '60.00 s')", () => {
    expect(formatDuration(59.999)).toBe("1 min 0 s");
  });
  // Para >= 1 min los segundos se redondean (antes se truncaban): 125.9 -> 126 s.
  it.each([
    [0.999, "999 ms"],
    [0.9994, "999 ms"],
    [1, "1.00 s"],
    [59.99, "59.99 s"],
    [59.994, "59.99 s"],
    [59.995, "1 min 0 s"],
    [60, "1 min 0 s"],
    [125.9, "2 min 6 s"],
    [3599.6, "1 h 0 min"],
    [3600, "1 h 0 min"],
  ])("borde %s -> %s", (n, out) => expect(formatDuration(n)).toBe(out));
});

describe("formatTime", () => {
  it("epoch conocido -> UTC exacto", () => {
    expect(formatTime(1700000000.123)).toBe("22:13:20.123 UTC");
    expect(formatTime(0)).toBe("00:00:00.000 UTC");
  });
  it("NaN -> —", () => expect(formatTime(NaN)).toBe("—"));
});

describe("formatEndpoint", () => {
  it("IPv4 con y sin puerto", () => {
    expect(formatEndpoint("10.0.0.1", 80)).toBe("10.0.0.1:80");
    expect(formatEndpoint("10.0.0.1")).toBe("10.0.0.1");
  });
  it("IPv6 con corchetes con puerto, sin ellos sin puerto", () => {
    expect(formatEndpoint("fe80::1", 443)).toBe("[fe80::1]:443");
    expect(formatEndpoint("fe80::1")).toBe("fe80::1");
  });
  it("puerto null/undefined/0", () => {
    expect(formatEndpoint("1.1.1.1", null)).toBe("1.1.1.1");
    expect(formatEndpoint("1.1.1.1", undefined)).toBe("1.1.1.1");
    expect(formatEndpoint("1.1.1.1", 0)).toBe("1.1.1.1:0");
  });
  it("ip vacía -> —", () => {
    expect(formatEndpoint("", 80)).toBe("—");
    expect(formatEndpoint(null, 80)).toBe("—");
  });
});

describe("severityLabel", () => {
  it("conocidas", () => {
    expect(["low", "medium", "high", "critical"].map(severityLabel)).toEqual(["Baja", "Media", "Alta", "Crítica"]);
  });
  it("desconocida devuelve el valor", () => expect(severityLabel("weird")).toBe("weird"));
});

describe("percent", () => {
  it("total 0 -> 0", () => {
    expect(percent(5, 0)).toBe(0);
    expect(percent(0, 0)).toBe(0);
  });
  it("redondea a 1 decimal", () => {
    expect(percent(1, 3)).toBe(33.3);
    expect(percent(2, 3)).toBe(66.7);
    expect(percent(1, 1)).toBe(100);
  });
});
