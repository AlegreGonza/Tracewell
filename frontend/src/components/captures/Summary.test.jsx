import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import Summary from "./Summary.jsx";

const base = (stats = {}, extra = {}) => ({
  source: "demo.pcap",
  format: "pcap",
  linktype: 1,
  snaplen: 65535,
  alerts: 2,
  rules: 5,
  stats: {
    sessions: 3,
    packets: 100,
    bytes: 2048,
    by_protocol: {
      UDP: { sessions: 1, packets: 10, bytes: 100 },
      TCP: { sessions: 2, packets: 90, bytes: 1948 },
    },
    non_ip: 4,
    malformed: 1,
    ...stats,
  },
  ...extra,
});

const stat = (label) => screen.getByText(label).parentElement.querySelector("dd").textContent;

describe("Summary", () => {
  it("muestra los totales y el origen", () => {
    render(<Summary capture={base()} />);
    expect(stat("Sesiones")).toBe("3");
    expect(stat("Paquetes")).toBe("100");
    expect(stat("Tráfico")).toBe("2.00 KB");
    expect(stat("Alertas")).toBe("2");
    expect(stat("Sin IP (ARP…)")).toBe("4");
    expect(stat("Dañados")).toBe("1");
    expect(screen.getByText(/demo\.pcap · pcap · snaplen 65535/)).toBeInTheDocument();
  });

  it("la leyenda de protocolos no usa la clase de las barras sueltas (gráficos de latencia)", () => {
    render(<Summary capture={base()} />);
    const lista = screen.getAllByRole("listitem")[0].parentElement;
    expect(lista).toHaveClass("proto-legend");
    expect(lista).not.toHaveClass("bars");
  });

  it("muestra non_ip y dañados SIEMPRE, incluso en 0", () => {
    render(<Summary capture={base({ non_ip: 0, malformed: 0 })} />);
    expect(stat("Sin IP (ARP…)")).toBe("0");
    expect(stat("Dañados")).toBe("0");
  });

  it("ordena las barras por paquetes (desc) con porcentaje", () => {
    render(<Summary capture={base()} />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("TCP");
    expect(items[0]).toHaveTextContent("90%");
    expect(items[1]).toHaveTextContent("UDP");
    expect(within(items[1]).getByText(/10 paq\./)).toBeInTheDocument();
  });

  it("sin sesiones: mensaje y sin barras, sin romper con total 0", () => {
    render(<Summary capture={base({ sessions: 0, packets: 0, bytes: 0, by_protocol: {} })} />);
    expect(screen.getByText("Sin sesiones.")).toBeInTheDocument();
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
    expect(stat("Paquetes")).toBe("0");
  });

  it("sin snaplen no lo muestra", () => {
    render(<Summary capture={base({}, { snaplen: 0 })} />);
    expect(screen.queryByText(/snaplen/)).toBeNull();
  });

  describe("aviso de análisis parcial", () => {
    it("truncated true: muestra el aviso con el número formateado es-AR", () => {
      render(<Summary capture={base({ truncated: true, untracked_packets: 1234567 })} />);
      const note = screen.getByRole("note");
      expect(note).toHaveTextContent(/Análisis parcial/);
      expect(note).toHaveTextContent("1.234.567");
    });

    it("truncated false o ausente: no muestra el aviso", () => {
      const { unmount } = render(<Summary capture={base({ truncated: false, untracked_packets: 5 })} />);
      expect(screen.queryByRole("note")).toBeNull();
      expect(screen.queryByText(/Análisis parcial/)).toBeNull();
      unmount();
      render(<Summary capture={base()} />);
      expect(screen.queryByRole("note")).toBeNull();
    });

    it("truncated true sin untracked_packets: muestra 0 sin romper", () => {
      render(<Summary capture={base({ truncated: true })} />);
      expect(screen.getByRole("note")).toHaveTextContent(/descartaron 0 paquetes/);
    });

    it("convive con las métricas", () => {
      render(<Summary capture={base({ truncated: true, untracked_packets: 10 })} />);
      expect(screen.getByRole("note")).toBeInTheDocument();
      expect(stat("Sesiones")).toBe("3");
      expect(stat("Paquetes")).toBe("100");
      expect(stat("Sin IP (ARP…)")).toBe("4");
      expect(stat("Dañados")).toBe("1");
    });

    it("no interpreta HTML hostil en source", () => {
      const { container } = render(
        <Summary
          capture={base({ truncated: true, untracked_packets: 1 }, { source: "<img src=x onerror=alert(1)>.pcap" })}
        />,
      );
      expect(container.querySelector("img")).toBeNull();
      expect(screen.getByText(/<img src=x onerror=alert\(1\)>\.pcap/)).toBeInTheDocument();
    });
  });
});
