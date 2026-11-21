import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { hosts: vi.fn() } }));
import { api } from "../../api/client.js";
import TopTalkers from "./TopTalkers.jsx";

const host = (ip, bytes, over = {}) => ({ ip, bytes, name: null, owner: null, role_label: null, ...over });
let onError, onFilterIp;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  onFilterIp = vi.fn();
});
const show = () => render(<TopTalkers refreshKey={0} onError={onError} onFilterIp={onFilterIp} />);

describe("TopTalkers", () => {
  it("pide los equipos con signal y muestra solo los 5 primeros", async () => {
    api.hosts.mockResolvedValue({ items: Array.from({ length: 8 }, (_, i) => host(`10.0.0.${i + 1}`, 1000 * (8 - i))) });
    show();
    expect(await screen.findByRole("heading", { name: /Quién más habla/ })).toBeInTheDocument();
    expect(api.hosts).toHaveBeenCalledWith(expect.any(AbortSignal));
    const items = within(screen.getByRole("list")).getAllByRole("listitem");
    expect(items).toHaveLength(5);
    expect(items[0]).toHaveTextContent("10.0.0.1");
    expect(screen.queryByText("10.0.0.6")).toBeNull();
  });

  it("muestra nombre, dueño o rol cuando hay", async () => {
    api.hosts.mockResolvedValue({ items: [host("8.8.8.8", 2048, { name: "dns.google" }), host("1.1.1.1", 1024, { owner: "Cloudflare" }), host("10.0.0.1", 10, { role_label: "Tu equipo" })] });
    show();
    await screen.findByText("dns.google");
    expect(screen.getByText("Cloudflare")).toBeInTheDocument();
    expect(screen.getByText("Tu equipo")).toBeInTheDocument();
  });

  it("la barra más larga mide 100% y las demás son proporcionales (mínimo 3%)", async () => {
    api.hosts.mockResolvedValue({ items: [host("1.1.1.1", 1000), host("2.2.2.2", 500), host("3.3.3.3", 1)] });
    const { container } = show();
    await screen.findByRole("button", { name: "1.1.1.1" });
    const widths = Array.from(container.querySelectorAll(".talkers-track i")).map((i) => i.style.width);
    expect(widths).toEqual(["100%", "50%", "3%"]);
  });

  it("el botón con la IP llama a onFilterIp con esa IP", async () => {
    api.hosts.mockResolvedValue({ items: [host("10.0.0.7", 5), host("10.0.0.8", 4)] });
    show();
    await userEvent.click(await screen.findByRole("button", { name: "10.0.0.8" }));
    expect(onFilterIp).toHaveBeenCalledTimes(1);
    expect(onFilterIp).toHaveBeenCalledWith("10.0.0.8");
  });

  it("sin equipos no dibuja nada", async () => {
    api.hosts.mockResolvedValue({ items: [] });
    const { container } = show();
    await waitFor(() => expect(api.hosts).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 10));
    expect(container).toBeEmptyDOMElement();
  });

  it("un error se informa por onError, salvo AbortError", async () => {
    api.hosts.mockRejectedValue(new Error("roto"));
    show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("roto"));
    onError.mockClear();
    api.hosts.mockRejectedValue(Object.assign(new Error("x"), { name: "AbortError" }));
    show();
    await new Promise((r) => setTimeout(r, 10));
    expect(onError).not.toHaveBeenCalled();
  });

  it("los nombres hostiles se ven como texto", async () => {
    const evil = "<script>alert(1)</script>";
    api.hosts.mockResolvedValue({ items: [host("6.6.6.6", 9, { name: evil })] });
    const { container } = show();
    expect(await screen.findByText(evil)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});
