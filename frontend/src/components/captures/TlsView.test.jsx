import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { sessionTls: vi.fn() } }));
import { api } from "../../api/client.js";
import TlsView, { describeJa4 } from "./TlsView.jsx";

const session = { id: 6, protocol: "TCP" };
const cert = (over = {}) => ({
  subject: "www.example.com", issuer: "Some CA", not_before: "2024-01-01T00:00:00+00:00", not_after: "2026-01-01T00:00:00+00:00",
  self_signed: false, expired: false, not_yet_valid: false, names: ["www.example.com", "example.com"], sha256: "c".repeat(64), ...over,
});
const tls = (over = {}) => ({
  tls: true, incomplete: false,
  client: { ja4: "t13d1516h2_8daaf6152771_02713d6af862", sni: "www.example.com", alpn: "h2", ciphers: 15, complete: true },
  server: { version: "TLS 1.2", cipher: "ECDHE-RSA-AES128-GCM-SHA256" }, certificate: cert(), certificate_hidden: false, ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.sessionTls.mockResolvedValue(tls());
});
const show = (props = {}) => render(<TlsView session={session} onError={onError} {...props} />);

describe("describeJa4", () => {
  it("la huella de Chrome se lee frase por frase", () => {
    expect(describeJa4("t13d1516h2_8daaf6152771_02713d6af862")).toEqual([
      "TCP", "TLS 1.3", "pide un sitio por nombre (SNI)", "15 cifrados ofrecidos", "16 extensiones", "HTTP/2"]);
  });
  it("solo importa la primera parte (antes del primer _)", () => {
    expect(describeJa4("t13d1516h2")).toEqual(describeJa4("t13d1516h2_x_y"));
  });
  it("q es QUIC", () => expect(describeJa4("q13d0310h3")[0]).toBe("QUIC"));
  it("i: no manda nombre de sitio; d: sí", () => {
    expect(describeJa4("t12i0510h1")[2]).toBe("no manda nombre de sitio");
    expect(describeJa4("t12d0510h1")[2]).toBe("pide un sitio por nombre (SNI)");
  });
  it.each([["13", "TLS 1.3"], ["12", "TLS 1.2"], ["11", "TLS 1.1"], ["10", "TLS 1.0"], ["s3", "SSL 3.0"], ["s2", "SSL 2.0"], ["00", "versión 00"], ["99", "versión 99"]])(
    "versión %s -> %s", (code, text) => expect(describeJa4(`t${code}d1516h2`)[1]).toBe(text));
  it.each([["h2", "HTTP/2"], ["h1", "HTTP/1.1"], ["00", "sin protocolo de aplicación (ALPN)"], ["zz", "ALPN zz"], ["s1", "ALPN s1"]])(
    "ALPN %s -> %s", (code, text) => expect(describeJa4(`t13d1516${code}`)[5]).toBe(text));
  it("los conteos quitan los ceros a la izquierda", () => {
    const d = describeJa4("t13d0905h2");
    expect(d[3]).toBe("9 cifrados ofrecidos");
    expect(d[4]).toBe("5 extensiones");
    expect(describeJa4("t13d9999h2").slice(3, 5)).toEqual(["99 cifrados ofrecidos", "99 extensiones"]);
  });
  it.each([[""], ["t13"], ["t13d1516h2x"], ["t13d1516h"], [null], [undefined], [42], ["_abc_def"]])("malformado %j -> []", (v) => expect(describeJa4(v)).toEqual([]));
  it("cuenta no numérica no rompe", () => {
    expect(describeJa4("t13dxx16h2")[3]).toBe("NaN cifrados ofrecidos");
  });
});

describe("TlsView", () => {
  it("no dibuja nada mientras carga", () => {
    api.sessionTls.mockReturnValue(new Promise(() => {}));
    expect(show().container).toBeEmptyDOMElement();
  });

  it("una sesión que no es TCP no pide ni dibuja", async () => {
    const { container } = show({ session: { id: 1, protocol: "UDP" } });
    await new Promise((r) => setTimeout(r, 0));
    expect(api.sessionTls).not.toHaveBeenCalled();
    expect(container).toBeEmptyDOMElement();
  });

  it.each([[{ tls: false }], [{ tls: false, incomplete: true }], [null]])("tls falso o respuesta nula (%j) no dibuja nada", async (resp) => {
    api.sessionTls.mockResolvedValue(resp);
    const { container } = show();
    await waitFor(() => expect(api.sessionTls).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("título con las ayudas de TLS y JA4", async () => {
    show();
    expect(await screen.findByRole("heading", { name: /^TLS \(cifrado\)/ })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Ayuda: / })).toHaveLength(2);
  });

  it("muestra sitio, versión, cifrado y huella", async () => {
    const { container } = show();
    await screen.findByRole("heading", { name: /^TLS/ });
    const text = container.textContent;
    expect(text).toContain("Sitio pedido (SNI)www.example.com");
    expect(text).toContain("Versión acordadaTLS 1.2");
    expect(text).toContain("CifradoECDHE-RSA-AES128-GCM-SHA256");
    expect(screen.getByText("t13d1516h2_8daaf6152771_02713d6af862")).toHaveClass("mono");
  });

  it("'Se lee así' traduce la huella", async () => {
    show();
    expect(await screen.findByText("Se lee así: TCP · TLS 1.3 · pide un sitio por nombre (SNI) · 15 cifrados ofrecidos · 16 extensiones · HTTP/2.")).toBeInTheDocument();
  });

  it("huella con formato raro: se muestra pero sin 'Se lee así'", async () => {
    api.sessionTls.mockResolvedValue(tls({ client: { ja4: "raro", sni: null, alpn: null, ciphers: 1, complete: true } }));
    show();
    expect(await screen.findByText("raro")).toBeInTheDocument();
    expect(screen.queryByText(/Se lee así/)).toBeNull();
  });

  it("sin SNI muestra '—'", async () => {
    api.sessionTls.mockResolvedValue(tls({ client: { ja4: "t13i1516h2_a_b", sni: null, alpn: "h2", ciphers: 15, complete: true } }));
    const { container } = show();
    await screen.findByRole("heading", { name: /^TLS/ });
    expect(container.textContent).toContain("Sitio pedido (SNI)—");
  });

  it("hello incompleto: mensaje en vez de la huella", async () => {
    api.sessionTls.mockResolvedValue(tls({ client: { ja4: null, sni: "a.test", alpn: null, ciphers: 3, complete: false } }));
    const { container } = show();
    expect(await screen.findByText(/No se puede calcular: el saludo del cliente está incompleto/)).toBeInTheDocument();
    expect(container.querySelector("dd .mono.hash")).toBeNull();
    expect(screen.queryByText(/Se lee así/)).toBeNull();
  });

  it("sin respuesta del servidor: versión explicada y sin cifrado", async () => {
    api.sessionTls.mockResolvedValue(tls({ server: { version: null, cipher: null }, certificate: null }));
    const { container } = show();
    await screen.findByRole("heading", { name: /^TLS/ });
    expect(container.textContent).toContain("no se ve la respuesta del servidor");
    expect(screen.queryByText("Cifrado")).toBeNull();
  });

  describe("certificado", () => {
    it("sujeto, emisor, validez, nombres y huella", async () => {
      const { container } = show();
      await screen.findByRole("heading", { name: /^TLS/ });
      const c = container.querySelector(".file");
      expect(c.querySelector("strong")).toHaveTextContent("www.example.com");
      expect(c.textContent).toContain("Emitido por: Some CA");
      expect(c.textContent).toContain("Válido de 2024-01-01 a 2026-01-01");
      expect(c.textContent).toContain("Nombres: www.example.com, example.com");
      expect(c.textContent).toContain(`SHA-256: ${"c".repeat(64)}`);
    });

    it("sin badges cuando todo está bien", async () => {
      show();
      await screen.findByRole("heading", { name: /^TLS/ });
      for (const t of ["autofirmado", "vencido", "todavía no válido"]) expect(screen.queryByText(t)).toBeNull();
    });

    it("badges de autofirmado, vencido y todavía no válido", async () => {
      api.sessionTls.mockResolvedValue(tls({ certificate: cert({ self_signed: true, expired: true, not_yet_valid: true }) }));
      show();
      expect(await screen.findByText("autofirmado")).toBeInTheDocument();
      expect(screen.getByText("vencido")).toBeInTheDocument();
      expect(screen.getByText("todavía no válido")).toBeInTheDocument();
    });

    it("expired null (sin hora) no marca vencido", async () => {
      api.sessionTls.mockResolvedValue(tls({ certificate: cert({ expired: null, not_yet_valid: undefined }) }));
      show();
      await screen.findByRole("heading", { name: /^TLS/ });
      expect(screen.queryByText("vencido")).toBeNull();
      expect(screen.queryByText("todavía no válido")).toBeNull();
    });

    it("datos ausentes: '(sin nombre)', '—' y sin línea de nombres", async () => {
      api.sessionTls.mockResolvedValue(tls({ certificate: cert({ subject: null, issuer: null, not_before: null, not_after: null, names: [] }) }));
      const { container } = show();
      await screen.findByRole("heading", { name: /^TLS/ });
      const c = container.querySelector(".file");
      expect(c.textContent).toContain("(sin nombre)");
      expect(c.textContent).toContain("Emitido por: —");
      expect(c.textContent).toContain("Válido de — a —");
      expect(c.textContent).not.toContain("Nombres:");
    });

    it("names ausente no rompe", async () => {
      api.sessionTls.mockResolvedValue(tls({ certificate: cert({ names: undefined }) }));
      show();
      expect(await screen.findByRole("heading", { name: /^TLS/ })).toBeInTheDocument();
    });

    it("con certificado no aparece la nota de 'no se ve el certificado'", async () => {
      show();
      await screen.findByRole("heading", { name: /^TLS/ });
      expect(screen.queryByText(/No se ve el certificado en esta sesión/)).toBeNull();
    });
  });

  describe("certificado oculto o ausente", () => {
    it("TLS 1.3: aviso role=note y sin tarjeta ni nota adicional", async () => {
      api.sessionTls.mockResolvedValue(tls({ server: { version: "TLS 1.3", cipher: "TLS_AES_128_GCM_SHA256" }, certificate: null, certificate_hidden: true }));
      const { container } = show();
      expect(await screen.findByRole("note")).toHaveTextContent("En TLS 1.3 el certificado del servidor va cifrado");
      expect(container.querySelector(".file")).toBeNull();
      expect(screen.queryByText(/No se ve el certificado en esta sesión/)).toBeNull();
    });

    it("sin certificado y no oculto: nota explicativa", async () => {
      api.sessionTls.mockResolvedValue(tls({ certificate: null }));
      show();
      expect(await screen.findByText(/No se ve el certificado en esta sesión/)).toBeInTheDocument();
      expect(screen.queryByRole("note")).toBeNull();
    });
  });

  it("textos hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.sessionTls.mockResolvedValue(tls({
      client: { ja4: evil, sni: evil, alpn: evil, ciphers: 1, complete: true }, server: { version: evil, cipher: evil },
      certificate: cert({ subject: evil, issuer: evil, names: [evil], sha256: evil }),
    }));
    const { container } = show();
    await screen.findByRole("heading", { name: /^TLS/ });
    expect(container.querySelector("img")).toBeNull();
  });

  it("pide por id con señal de aborto; al cambiar de sesión vuelve a pedir y borra lo anterior", async () => {
    const { rerender, container } = show();
    await screen.findByRole("heading", { name: /^TLS/ });
    expect(api.sessionTls).toHaveBeenCalledWith(6, expect.any(AbortSignal));
    api.sessionTls.mockResolvedValue({ tls: false });
    rerender(<TlsView session={{ id: 7, protocol: "TCP" }} onError={onError} />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
    expect(api.sessionTls).toHaveBeenLastCalledWith(7, expect.any(AbortSignal));
    expect(api.sessionTls.mock.calls[0][1].aborted).toBe(true);
  });

  it("error -> onError; AbortError no; desmontar aborta", async () => {
    api.sessionTls.mockRejectedValue(new Error("tls roto"));
    const a = show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("tls roto"));
    a.unmount();
    api.sessionTls.mockRejectedValue(Object.assign(new Error("x"), { name: "AbortError" }));
    const b = show();
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).toHaveBeenCalledTimes(1);
    const signal = api.sessionTls.mock.calls.at(-1)[1];
    b.unmount();
    expect(signal.aborted).toBe(true);
  });

  it("las ayudas de TLS y JA4 se abren", async () => {
    show();
    await screen.findByRole("heading", { name: /^TLS/ });
    const [a, b] = screen.getAllByRole("button", { name: /^Ayuda: / });
    await userEvent.click(a);
    await userEvent.click(b);
    expect(screen.getAllByRole("note")).toHaveLength(2);
  });
});
