import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { hostsByMac: vi.fn() } }));
import { api } from "../../api/client.js";
import MacGroups from "./MacGroups.jsx";

const group = (over = {}) => ({
  mac: "00:11:22:33:44:55", ips: ["192.168.1.10", "fd00::10"], names: [], sessions: 3, bytes: 2048, shared: true,
  hint: "Varias IP con la misma MAC: puede ser el mismo equipo con IPv4 e IPv6.", ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.hostsByMac.mockResolvedValue({ total: 2, items: [group(), group({ mac: "aa:bb:cc:dd:ee:ff", ips: ["192.168.1.1"], shared: false, hint: "" })] });
});

describe("MacGroups", () => {
  it("lista cada MAC con sus IP y la pista", async () => {
    render(<MacGroups refreshKey={0} onError={onError} />);
    expect(await screen.findByText("00:11:22:33:44:55")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "fd00::10" })).toBeInTheDocument();
    expect(screen.getByText(/IPv4 e IPv6/)).toBeInTheDocument();
    expect(screen.getByText(/2 MAC · 1 con varias IP/)).toBeInTheDocument();
  });

  it("la IP es un botón que filtra las sesiones", async () => {
    const onFilterIp = vi.fn();
    render(<MacGroups refreshKey={0} onError={onError} onFilterIp={onFilterIp} />);
    await userEvent.click(await screen.findByRole("button", { name: "192.168.1.1" }));
    expect(onFilterIp).toHaveBeenCalledWith("192.168.1.1");
  });

  it("sin grupos no muestra la tarjeta", async () => {
    api.hostsByMac.mockResolvedValue({ total: 0, items: [] });
    const { container } = render(<MacGroups refreshKey={0} onError={onError} />);
    await vi.waitFor(() => expect(api.hostsByMac).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("un error de la API se informa", async () => {
    api.hostsByMac.mockRejectedValue(new Error("409"));
    render(<MacGroups refreshKey={0} onError={onError} />);
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("409"));
  });

  it("el texto de la pista no se interpreta como HTML", async () => {
    api.hostsByMac.mockResolvedValue({ total: 1, items: [group({ hint: "<img src=x onerror=alert(1)>" })] });
    render(<MacGroups refreshKey={0} onError={onError} />);
    await screen.findByText("00:11:22:33:44:55");
    expect(document.querySelector("img")).toBeNull();
  });
});
