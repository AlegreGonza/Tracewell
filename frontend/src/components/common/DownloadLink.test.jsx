import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("../../api/token.js", () => ({ getToken: vi.fn() }));
vi.mock("../../api/client.js", () => ({ api: { ticketUrl: vi.fn() } }));

import { getToken } from "../../api/token.js";
import { api } from "../../api/client.js";
import DownloadLink from "./DownloadLink.jsx";

let clicked;

beforeEach(() => {
  clicked = [];
  // jsdom no baja archivos: se anota a qué URL apuntaba el enlace temporal al hacerle clic
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function () {
    clicked.push({ href: this.getAttribute("href"), download: this.getAttribute("download") });
  });
});

afterEach(() => vi.restoreAllMocks());

describe("DownloadLink", () => {
  it("sin token es un enlace normal: href y download, sin pedir ticket", () => {
    getToken.mockReturnValue(null);
    render(<DownloadLink href="/api/export?ip=1.2.3.4" download="x.json">Exportar</DownloadLink>);
    const a = screen.getByRole("link", { name: "Exportar" });
    expect(a).toHaveAttribute("href", "/api/export?ip=1.2.3.4");
    expect(a).toHaveAttribute("download", "x.json");
    fireEvent.click(a);
    expect(api.ticketUrl).not.toHaveBeenCalled();
  });

  it("con token pide un ticket y baja con esa URL (no con la original)", async () => {
    getToken.mockReturnValue("tok");
    api.ticketUrl.mockResolvedValue("/api/report?ticket=abc");
    render(<DownloadLink href="/api/report" download="informe.html">Informe</DownloadLink>);
    fireEvent.click(screen.getByRole("link", { name: "Informe" }));
    await waitFor(() => expect(clicked).toEqual([{ href: "/api/report?ticket=abc", download: "informe.html" }]));
    expect(api.ticketUrl).toHaveBeenCalledWith("/api/report");
  });

  it("respeta el onClick: si lo cancela no se pide ticket ni se baja nada", async () => {
    getToken.mockReturnValue("tok");
    render(
      <DownloadLink href="/api/report" download onClick={(e) => e.preventDefault()}>Informe</DownloadLink>,
    );
    fireEvent.click(screen.getByRole("link", { name: "Informe" }));
    await Promise.resolve();
    expect(api.ticketUrl).not.toHaveBeenCalled();
    expect(clicked).toEqual([]);
  });

  it("si el ticket falla avisa en un role=alert y no baja nada", async () => {
    getToken.mockReturnValue("tok");
    api.ticketUrl.mockRejectedValue(new Error("401"));
    render(<DownloadLink href="/api/report" download>Informe</DownloadLink>);
    fireEvent.click(screen.getByRole("link", { name: "Informe" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("No se pudo preparar la descarga");
    expect(clicked).toEqual([]);
  });
});
